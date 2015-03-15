#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include <user/syscall.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/mpage.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static hash_action_func free_mpte_and_frame_or_swap;
static void free_mpte_and_frame_or_swap 
    (struct hash_elem *e, void *aux UNUSED);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;

  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  struct thread *cur = thread_current ();
  tid_t temp = TID_ERROR;
  if (!list_empty (&cur->children))
    {
      temp = list_entry (list_begin (&cur->children), 
          struct child_process, elem)->tid;
    }
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    { 
      palloc_free_page (fn_copy); 
    }
  else
    {
      sema_down (&cur->create_sema);
      if (list_empty (&cur->children))
        {
          tid = TID_ERROR;
        }
      else
        {
          tid = list_entry (list_begin (&cur->children), 
                           struct child_process, elem)->tid;
          if (tid == temp)
            tid = TID_ERROR;
        }
    }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  enum intr_level old_level;
  struct thread *cur = thread_current ();
  struct thread *parent;

  #ifdef VM
    mpage_init (&cur->mpage_hash,&cur->spt_lock);
    list_init (&cur->mmap_list);
    cur->next_mid = 1;
  #endif

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    {
      
      old_level = intr_disable ();
      if ((parent = cur->parent) != NULL)
        sema_up (&parent->create_sema);
      intr_set_level (old_level);
      
      thread_exit ();
    }
  else
    {
      struct child_process *child = 
          (struct child_process *) malloc (sizeof (struct child_process));
      cur->elem_in_parent = child;
      child->tid = cur->tid;
      child->status = STATUS_ERROR;
      child->thread = cur;
      sema_init (&child->wait_sema, 0);
      if ((parent = cur->parent) != NULL)
        {
          list_push_front (&parent->children, &child->elem);
          sema_up (&parent->create_sema);
          /* after this point, 'child' is to be freed by parent, so
             child basically lives and dies with parent */
        }
      else
        {
          free (child);
        }
    }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid) 
{
  struct thread *cur = thread_current ();
  struct child_process *child = NULL;
  int status;

  struct list_elem *e;
  for (e = list_begin (&cur->children); e != list_end (&cur->children);
       e = list_next (e))
    {
      struct child_process *c = 
        list_entry (e, struct child_process, elem);
      if (c->tid == child_tid)
        {
          child = c;
          break;
        }
    }

  if (child == NULL)
    {
      status = STATUS_ERROR;
    }
  else
    {
      sema_down (&child->wait_sema);
      status = child->status;
      list_remove (&child->elem);
      free (child);
    }

  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  struct list_elem *m_elem;
  for (m_elem = list_begin (&cur->mmap_list); 
        m_elem != list_end (&cur->mmap_list);)
    { 
      struct mmap_entry *m = list_entry (m_elem, struct mmap_entry, elem);
      m_elem = list_next (m_elem);
      syscall_munmap (m);
    }
  lock_acquire(&cur->spt_lock);
  hash_destroy (&cur->mpage_hash, free_mpte_and_frame_or_swap);
  lock_release(&cur->spt_lock);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  if (cur->exec_name != NULL)
    {
      printf ("%s: exit(%d)\n", cur->exec_name, cur->process_status);
      free (cur->exec_name);
    }

  enum intr_level old_level;
  old_level = intr_disable ();
  if ((cur->parent != NULL) && (cur->elem_in_parent != NULL))
    {
      cur->elem_in_parent->thread = NULL;
      sema_up (&cur->elem_in_parent->wait_sema);
    }

  struct list_elem *e;
  for (e = list_begin (&cur->children); e != list_end (&cur->children);
       e = list_next (e))
    { 
      struct child_process *c = 
          list_entry (e, struct child_process, elem);
      if (c->thread != NULL)
        c->thread->parent = NULL;
      free (c);
    }

  intr_set_level (old_level);
  if (cur->exec_file != NULL)
    file_close (cur->exec_file);
  struct list_elem *f_elem;
  for (f_elem = list_begin (&cur->open_files); 
      f_elem != list_end (&cur->open_files);)
    {
      struct fd_file *f = list_entry (f_elem, struct fd_file, elem);
      file_close (f->file);
      f_elem = list_next (f_elem);
      free (f);
    } 
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (const char *file_name, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  char *exec_name = NULL;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */

  /* Extract executable file name. */
  for (i = 0; file_name[i] != '\0' && file_name[i] != ' '; i++)
    continue;
  exec_name = (char *) malloc ((i + 1) * sizeof (char));
  strlcpy (exec_name, file_name, i + 1);

  file = filesys_open (exec_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", exec_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", exec_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
               enum page_type type = (writable == true) ? TYPE_LOADING_WRITABLE : TYPE_LOADING;
              if (!load_segment_lazy (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, type))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (file_name, esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (file != NULL)
    file_deny_write (file);
  t->exec_file = file;
  t->exec_name = exec_name;
  return success;
}



static void
free_mpte_and_frame_or_swap (struct hash_elem *e, void *aux UNUSED)
{
  struct mpage_entry *mpte =
    hash_entry (e, struct mpage_entry, elem);
  
   if (frame_exist_and_free (mpte))
    {
      struct thread *cur = thread_current ();
      pagedir_clear_page(cur->pagedir, mpte->uaddr);
    }
  else
    {
      switch (mpte->type)
        {
          case TYPE_STACK:
          case TYPE_LOADED_WRITABLE:
            lock_acquire (&swap_lock);
            swap_reset_slot (mpte->swap_sector);
            lock_release (&swap_lock);
            break;
          default:
            break;
        }
    }
  free (mpte);
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

bool
load_segment_lazy (struct file *file, off_t ofs, uint8_t *upage,
                   uint32_t read_bytes, uint32_t zero_bytes, enum page_type type)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  uint8_t *input_page = upage;
  while (read_bytes > 0 || zero_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      struct thread *t = thread_current();
      struct mpage_entry *mpte = (struct mpage_entry *) 
                                     malloc (sizeof (struct mpage_entry));
      if (mpte == NULL) 
        {
          lock_acquire(&t->spt_lock);
          while(upage>=input_page)
            {
              struct mpage_entry *m = mpage_lookup (&t->mpage_hash, upage);
              hash_delete (&t->mpage_hash,&m->elem);
              free(m);
              upage-=PGSIZE;
            }
          lock_release(&t->spt_lock);
          return false;
        }
      lock_acquire(&t->spt_lock);
      mpte->uaddr = upage;
      mpte->type = type;
      mpte->fte = NULL;
      mpte->swap_sector = 0;
      mpte->file = file;
      mpte->ofs = ofs;
      mpte->length = page_read_bytes;
      hash_insert (&t->mpage_hash, &mpte->elem);
      lock_release(&t->spt_lock);
      ofs  += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (const char *file_name, void **esp) 
{
  void *kpage;
  bool success = false;

  struct frame_entry *fte = frame_get_frame_pinned (true);
  fte->t = thread_current ();
  kpage = fte->paddr;
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        {
          struct mpage_entry *mpte = (struct mpage_entry *)
                                      malloc (sizeof (struct mpage_entry));
          if (mpte == NULL)
            {
              success = false;
            }
          else
            { 
              struct thread *t = thread_current();
              lock_acquire(&t->spt_lock);
              mpte->uaddr = ((uint8_t *) PHYS_BASE) - PGSIZE;
              mpte->type = TYPE_STACK;
              mpte->fte = fte;
              mpte->swap_sector = 0;
              mpte->file = NULL;
              mpte->ofs = 0;
              mpte->length = 0;
              struct thread *cur = thread_current ();
              hash_insert (&cur->mpage_hash, &mpte->elem);
              fte->mpte = mpte;
              lock_release(&t->spt_lock);
              success = true;
              frame_unpin_frame (kpage);
            }
        }
      if (success)
        {
          char *fn_copy, *token, *save_ptr;
          int argc = 0, argv_char_cnt = 0;
          char *argv_bgn, **stack_bgn; 
          
          fn_copy = palloc_get_page (0);
          if (fn_copy == NULL) return false;
          
          strlcpy (fn_copy, file_name, PGSIZE);
          for (token = strtok_r (fn_copy, " ", &save_ptr); token != NULL;
               token = strtok_r (NULL, " ", &save_ptr))
            {
              argc ++;
              argv_char_cnt += strlen (token) + 1;
            }
          argv_bgn = (char *) (PHYS_BASE - argv_char_cnt);
          
          char * wd_al;
          for (wd_al = argv_bgn - 1; (int) wd_al >= ((int)(argv_bgn) / 4 * 4);
               wd_al --)
            *wd_al = 0;
          
          stack_bgn = (char **) ((unsigned int)(argv_bgn) / 4 * 4) - argc - 4;
          
          if ((unsigned int)stack_bgn <= (unsigned int)(PHYS_BASE - PGSIZE))
            {
              success = false;
              goto done;
            }

          *esp = (void *) stack_bgn;
          
          *((void (**) ()) stack_bgn++) = (void (*) ()) 0;  // return address
          *((int *) stack_bgn++) = argc; // argc
          *((char ***) stack_bgn) = stack_bgn + 1; // argv
          stack_bgn ++;
          // argv[0] and argv[0][...]
          strlcpy (fn_copy, file_name, PGSIZE);
          for (token = strtok_r (fn_copy, " ", &save_ptr); token != NULL;
               token = strtok_r (NULL, " ", &save_ptr))
            {
              int argv_length = strlen (token);
              *stack_bgn++ = argv_bgn;
              strlcpy (argv_bgn, token, argv_length + 1);
              argv_bgn += argv_length + 1;
            }
          *stack_bgn = (char *) 0;
          
        done:
            palloc_free_page (fn_copy);
        }
      else
        frame_free_frame (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
