#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/frame.h"
#include "vm/mpage.h"
#include "vm/swap.h"

#define STACK_LIMIT 0x80000

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);
static bool install_page (void *upage, void *kpage, bool writable);


/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;
  
  if (not_present)
    {
    /* not present */
    /* check if the fault address is in mpage_hash */
    struct hash *mpage_hash = &thread_current() -> mpage_hash;
    struct thread *t = thread_current();
    lock_acquire(&t->spt_lock);
    struct mpage_entry *mpte = 
        mpage_lookup (mpage_hash, pg_round_down (fault_addr));
    lock_release(&t->spt_lock);
 
    if (mpte != NULL)
      { 
        struct frame_entry *fte;
        void *kpage;
        bool writable = false;
        fte = frame_get_frame_pinned (true);
        if (fte == NULL)
          {
            printf ("ERROR: fte == NULL, no more frame\n");
            kill (f);
            return;
          }
        kpage = fte->paddr;
        struct file *file = NULL;
        switch (mpte->type)
          {
            case TYPE_STACK:
            case TYPE_LOADED_WRITABLE:
              lock_acquire (&swap_disk_lock);
              swap_read_slot (mpte->swap_sector, kpage);
              lock_release (&swap_disk_lock);
              lock_acquire (&swap_lock);
              swap_reset_slot (mpte->swap_sector);
              lock_release (&swap_lock);
              writable = true;
              break;
            case TYPE_ZERO:
              writable = true;
              break;
            case TYPE_LOADING:
            case TYPE_LOADING_WRITABLE:
            case TYPE_FILE:
              /* load page from disk */
              file = mpte->file;
              file_seek (file, mpte->ofs);
              int bytes_read = file_read (file, kpage, mpte->length);
              if (bytes_read != (int) mpte->length)
                {
                  printf ("ERROR: file_read != length\n");
                  frame_free_frame (kpage);
                  kill (f);
                  return;
                }
              writable = 
                    (mpte->type == TYPE_LOADING_WRITABLE) 
                    || (mpte->type == TYPE_FILE);
              break;
          }
        if (!install_page (mpte->uaddr, kpage, writable))
          {
            printf ("ERROR: install_page failed");
            frame_free_frame (kpage);
            kill (f);
            return;
          }
        fte->t = thread_current ();
        fte->mpte = mpte;
        mpte->fte = fte;
        frame_clean_dirty (mpte->uaddr, kpage);
        frame_unpin_frame (kpage);
        return;
      }
    else
      {
        /* stack growth or invalid access */
        struct thread *t = thread_current ();
        void *esp = user ? f->esp : t->syscall_esp;
        if (((((unsigned) esp <= (unsigned) fault_addr)
            || (((unsigned) esp - (unsigned) fault_addr) == 4)
            || (((unsigned) esp - (unsigned) fault_addr) == 32)))
            &&  ((unsigned) PHYS_BASE >= (unsigned) fault_addr)
            &&  ((unsigned) PHYS_BASE - (unsigned) esp <= STACK_LIMIT))
          {
            void *upage = pg_round_down (fault_addr);
            struct frame_entry *fte = frame_get_frame_pinned (true);
            if (fte == NULL)
              {
                printf ("ERROR: fte == NULL, no more frame\n");
                kill (f);
                return;
              }

            fte->t = t;
            uint8_t *kpage = fte->paddr;
            
            if (!install_page (upage, kpage, true))
              {
                printf ("ERROR: install_page failed");
                frame_free_frame (kpage);
                kill (f);
                return;
              }
            struct mpage_entry *mpte = 
                (struct mpage_entry *) malloc (sizeof (struct mpage_entry));
            ASSERT (mpte != NULL);
            mpte->uaddr = upage;
            mpte->type = TYPE_ZERO;
            mpte->fte = fte;
            mpte->swap_sector = 0;
            mpte->file = NULL;
            mpte->ofs = 0;
            mpte->length = 0;
            lock_acquire(&t->spt_lock);
            hash_insert (&t->mpage_hash, &mpte->elem);
            lock_release (&t->spt_lock);
            fte->mpte = mpte;
            frame_clean_dirty (upage, kpage);
            frame_unpin_frame (kpage);

            /* form upage to PHYS_BASE, continuous stack */
            upage = (void *) ((unsigned) upage + PGSIZE);
            struct mpage_entry query_mpte;
            while ((unsigned) upage < (unsigned) PHYS_BASE)
              {
                query_mpte.uaddr = upage;
                lock_acquire (&t->spt_lock);
                if (hash_find (&t->mpage_hash, &query_mpte.elem) == NULL)
                  {
                    struct mpage_entry *stack_mpte = (struct mpage_entry *)
                          malloc (sizeof (struct mpage_entry));
                    ASSERT (stack_mpte != NULL);
                    stack_mpte->uaddr = upage;
                    stack_mpte->type = TYPE_ZERO;
                    stack_mpte->fte = NULL;
                    stack_mpte->swap_sector = 0;
                    stack_mpte->file = NULL;
                    stack_mpte->ofs = 0;
                    stack_mpte->length = 0;
                    hash_insert (&t->mpage_hash, &stack_mpte->elem);
                  }
                lock_release (&t->spt_lock);
                upage = (void *) ((unsigned) upage + PGSIZE);
              }
            return;
          }
      }
    }
  /* rights violation and unhandled cases with not_present */
  if (!user)
    {
      f->eip = (void (*) (void)) f->eax;
      f->eax = 0xFFFFFFFF;
      return;
    }
  kill (f);
}

static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
