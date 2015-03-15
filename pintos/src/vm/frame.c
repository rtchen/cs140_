#include "vm/frame.h"

#include <list.h>
#include <stdint.h>
#include <stdlib.h>
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static bool frame_thread_check_dirty 
    (struct thread *t, void *uaddr, void *paddr);
static bool frame_thread_check_access 
    (struct thread *t, void *uaddr, void *paddr);
static void frame_thread_clean_access 
    (struct thread *t, void *uaddr, void *paddr);

static struct list_elem *clock_hand;
static struct lock frame_lock;

void
frame_init (void)
	{
		list_init (&frame_list);
		lock_init (&frame_lock);
    clock_hand = list_begin (&frame_list);
	}

struct frame_entry *
frame_get_frame_pinned (bool zero)
	{ 
    void *addr = NULL;
		if (zero)
			addr = palloc_get_page (PAL_USER | PAL_ZERO);
		else
			addr = palloc_get_page (PAL_USER);
		
    if (addr == NULL)
      { 
        lock_acquire (&frame_lock);
        struct frame_entry *fte = NULL;
        if (clock_hand == list_end (&frame_list))
          {
            clock_hand = list_begin (&frame_list);
          }

        struct list_elem *start = clock_hand;
        unsigned pinned_count = 0;

        while (true)
          { 
            struct frame_entry *f = 
                    list_entry (clock_hand, struct frame_entry, elem); 
            if (clock_hand == start)
              {
                if (pinned_count == list_size (&frame_list))
                  /* all frames are pinned */
                  break;
                else
                  pinned_count = 0;
              }

            if (f->pinned)
              { 
                pinned_count ++;
                clock_hand = list_next (clock_hand);
                if (clock_hand == list_end (&frame_list))
                  {
                    clock_hand = list_begin (&frame_list);
                  }
                continue;
              }

            bool access = 
                frame_thread_check_access (f->t, f->mpte->uaddr, f->paddr);
            frame_thread_clean_access (f->t, f->mpte->uaddr, f->paddr);
            
            if (access)
              { 
                clock_hand = list_next (clock_hand);
                if (clock_hand == list_end (&frame_list))
                  {
                    clock_hand = list_begin (&frame_list);
                  }
                continue;
              }
            else 
              { 
                clock_hand = list_next (clock_hand);
                if (clock_hand == list_end (&frame_list))
                  {
                    clock_hand = list_begin (&frame_list);
                  }
                fte = f;
                break;
              }
          }

        if (fte == NULL)
          {
            /* when all frames are pinned */
            lock_release (&frame_lock);
            return NULL;
          }

        fte->pinned = true;
        struct mpage_entry *mpte = fte->mpte; 
        
        lock_acquire(&fte->t->spt_lock);
        
        pagedir_clear_page (fte->t->pagedir, mpte->uaddr);
        bool dirty = 
            frame_thread_check_dirty (fte->t, fte->mpte->uaddr, fte->paddr);

        if (((mpte->type == TYPE_LOADING_WRITABLE) && (!dirty))
            || ((mpte->type == TYPE_ZERO) && (!dirty))
            || ((mpte->type == TYPE_FILE) && (!dirty))
            || ((mpte->type == TYPE_LOADING)) )
          {
            mpte->fte = NULL;
            lock_release (&frame_lock); 
            lock_release(&fte->t->spt_lock);
          } 
        else if (((mpte->type == TYPE_LOADING_WRITABLE) && (dirty)) 
                 || ((mpte->type == TYPE_ZERO) && (dirty))
                 || (mpte->type == TYPE_STACK)
                 || (mpte->type == TYPE_LOADED_WRITABLE) )
          { 
            lock_acquire (&swap_lock);
            size_t slot = swap_find_free_slot ();
            ASSERT (slot != SWAP_ERROR);
            lock_release (&swap_lock);
            mpte->fte = NULL;
            mpte->swap_sector = slot;
            switch (mpte->type)
              {
                case TYPE_LOADING_WRITABLE:
                  mpte->type = TYPE_LOADED_WRITABLE;
                  break;
                case TYPE_ZERO:
                  mpte->type = TYPE_STACK;
                  break;
                default:
                  break;
              }

            lock_acquire (&swap_disk_lock);
            lock_release (&frame_lock); 
            lock_release(&fte->t->spt_lock);
            /* release lock before swap disk operation */
            swap_write_slot (slot, fte->paddr);
            lock_release (&swap_disk_lock); 
          }
        else if ((mpte->type == TYPE_FILE) && (dirty)) 
          {
            mpte->fte = NULL;
            lock_release (&frame_lock); 
            lock_release(&fte->t->spt_lock);
            /* release lock before file operation */
            file_write_at (mpte->file, mpte->uaddr, mpte->length, mpte->ofs);
          }
        if (zero)
          {
             memset (fte->paddr, 0, PGSIZE);
          }
        fte->mpte = NULL;
        return fte;
      }
    /* addr != NULL */
		struct frame_entry *fte = 
            (struct frame_entry *) malloc (sizeof (struct frame_entry));
		ASSERT (fte != NULL); 
		fte->paddr = addr;
		fte->pinned = true;
		fte->mpte = NULL;
    //fte->t = thread_current();
    lock_acquire (&frame_lock);
    list_insert (list_end (&frame_list), &fte->elem);
    lock_release (&frame_lock);
		return fte;
}

void
frame_free_frame (void *paddr)
	{
    lock_acquire (&frame_lock);
		struct list_elem *e;
		ASSERT (pg_ofs (paddr) == 0);
		for (e = list_begin (&frame_list); e != list_end (&frame_list);
				 e = list_next (e))
			{
				struct frame_entry *fte = 
										list_entry (e, struct frame_entry, elem);
				if (fte->paddr == paddr)
					{
						palloc_free_page (paddr);
            if (clock_hand == e)
              {
                clock_hand = list_next (e);
              }
						list_remove (e);
            if (clock_hand == list_end (&frame_list))
              {
                clock_hand = list_begin (&frame_list);
              }
						free (fte);
						break;
					}
			}
    lock_release (&frame_lock);
	}


void
frame_unpin_frame (void *paddr)
	{
    lock_acquire (&frame_lock);
		struct list_elem *e;
		ASSERT (pg_ofs (paddr) == 0);
		for (e = list_begin (&frame_list); e != list_end (&frame_list);
				 e = list_next (e))
			{
				struct frame_entry *fte = 
										list_entry (e, struct frame_entry, elem);
				if (fte->paddr == paddr)
					{
						fte->pinned = false;
					}
			}
    lock_release (&frame_lock);
	}

bool
frame_exist_and_pin (struct mpage_entry *mpte)
	{
    lock_acquire (&frame_lock);
		if (mpte->fte != NULL)
			{
				mpte->fte->pinned = true;
        lock_release (&frame_lock);
				return true;
			}
    lock_release (&frame_lock);
		return false;
	}

bool 
frame_exist_and_free (struct mpage_entry *mpte)
	{
    lock_acquire (&frame_lock);
		bool exist = false;
		if (mpte->fte != NULL)
			{
				exist = true;
				palloc_free_page (mpte->fte->paddr);
				list_remove (&(mpte->fte->elem));
				free (mpte->fte);
				mpte->fte = NULL;
			}
    lock_release (&frame_lock);
		return exist;
	}

bool
frame_check_dirty (void *uaddr, void *paddr)
  {
    struct thread *cur = thread_current ();
    return frame_thread_check_dirty (cur, uaddr, paddr);
  }

void
frame_clean_dirty (void *uaddr, void *paddr)
  {
    struct thread *cur = thread_current ();
    pagedir_set_dirty (cur->pagedir, uaddr, false);
    pagedir_set_dirty (cur->pagedir, paddr, false);
  }

static bool
frame_thread_check_dirty (struct thread *t, void *uaddr, void *paddr)
  {
    bool u_dirty = pagedir_is_dirty (t->pagedir, uaddr);
    bool p_dirty = pagedir_is_dirty (t->pagedir, paddr);
    return u_dirty || p_dirty;
  }

static bool
frame_thread_check_access (struct thread *t, void *uaddr, void *paddr)
  {
    bool u_access = pagedir_is_accessed (t->pagedir, uaddr);
    bool p_access = pagedir_is_accessed (t->pagedir, paddr);
    return u_access || p_access;
  }

static void
frame_thread_clean_access (struct thread *t, void *uaddr, void *paddr)
  {
    pagedir_set_accessed (t->pagedir, uaddr, false);
    pagedir_set_accessed (t->pagedir, paddr, false);

  }
