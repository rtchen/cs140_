#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <hash.h>
#include <user/syscall.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "vm/mmap.h"
#include "vm/mpage.h"
#include <string.h>
#include "lib/round.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/free-map.h"

#define CONSOLE_CHUNK_SIZE 128
#define FD_MAX 32767	// INT_MAX
#define FD_ERROR -1
#define END_OF_TEXT 3

#define sys_arg(TYPE, INDEX)	\
		((TYPE)(validate_and_read_arg((uint32_t *)((TYPE *)f->esp + INDEX))))	

static void syscall_handler (struct intr_frame *);

static void sys_halt (void);
static void sys_exit (int status);
static pid_t sys_exec (const char *cmd_line);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file_name, unsigned initial_size);
static bool sys_remove (const char *file_name);
static int sys_open (const char *file_name);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);
static mapid_t sys_mmap (int fd, void *addr);
static void sys_munmap (mapid_t mapid);

static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static bool read_buffer (uint8_t *dst, const uint8_t *src, int size);
static bool write_buffer (uint8_t *dst, const uint8_t *src, int size);
static uint32_t validate_and_read_arg (uint32_t *uaddr);
static void validate_str (const char *str, int max_len);

static int get_next_fd (void);
static struct file * lookup_fd (int fd);
static mapid_t get_next_mid (void);
static struct mmap_entry * lookup_mid (mapid_t mid);
static bool sys_chdir(const char *dir);
static bool sys_mkdir(const char *dir);
static bool sys_readdir(int fd,char *name);
static bool sys_isdir(int fd);
static int sys_inumber(int fd);

void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* called when a process exits and release mmap resources */
void 
syscall_munmap (struct mmap_entry *mm_entry)
{
	struct thread *cur = thread_current ();
	size_t size = mm_entry->size;
  void *vaddr = mm_entry->vaddr;
	lock_acquire(&cur->spt_lock);
	struct hash *mpage_hash = &cur -> mpage_hash; 
	while(size>0)
		{
			struct mpage_entry *mpte = mpage_lookup (mpage_hash, vaddr); 
			ASSERT (mpte != NULL);
			if (frame_exist_and_pin (mpte)) 
				{
					if (frame_check_dirty (mpte->uaddr, mpte->fte->paddr))
						{
							file_write_at (mpte->file, mpte->uaddr, mpte->length, mpte->ofs);
						}
					frame_free_frame (mpte->fte->paddr);
					pagedir_clear_page (cur->pagedir, mpte->uaddr);
				}
			hash_delete (&cur->mpage_hash, &mpte->elem);
			vaddr += mpte->length;
			size-=mpte->length;
			free (mpte);
		}
	lock_release(&cur->spt_lock); 
	list_remove (&mm_entry->elem);
	file_close (mm_entry->file);
	free (mm_entry);
}	

static void
syscall_handler (struct intr_frame *f) 
{
	struct thread *t = thread_current ();
	t->syscall_esp = f->esp;

	int syscall_nr = sys_arg (int, 0);
	switch (syscall_nr)
		{
			case SYS_HALT:
				sys_halt ();
				break;
			case SYS_EXIT:
				sys_exit (sys_arg (int, 1));
				break;
			case SYS_EXEC:
				f->eax = (uint32_t) sys_exec (sys_arg (char *, 1));
				break;
			case SYS_WAIT:
				f->eax = (uint32_t) sys_wait (sys_arg (pid_t, 1));
				break;
			case SYS_CREATE:
				f->eax = (uint32_t) sys_create (sys_arg (char *, 1), 
																sys_arg (unsigned, 2));
				break;
			case SYS_REMOVE:
				f->eax = (uint32_t) sys_remove (sys_arg (char *, 1));
				break;
			case SYS_OPEN:
				f->eax = (uint32_t) sys_open (sys_arg (char *, 1));
				break;
			case SYS_FILESIZE:
				f->eax = (uint32_t) sys_filesize (sys_arg (int, 1));
				break;
			case SYS_READ:
				f->eax = (uint32_t) sys_read (sys_arg (int, 1), sys_arg (void *, 2), 
									sys_arg (unsigned, 3));
				break;
			case SYS_WRITE:
				f->eax = (uint32_t) sys_write (sys_arg (int, 1), sys_arg (void *, 2), 
					sys_arg (unsigned, 3));
				break;
			case SYS_SEEK:
				sys_seek (sys_arg (int, 1), sys_arg (unsigned, 2));
				break;
			case SYS_TELL:
				f->eax = (uint32_t) sys_tell (sys_arg (int, 1));
				break;
			case SYS_CLOSE:
				sys_close (sys_arg (int, 1));
				break;
			case SYS_MMAP:
				f->eax = (mapid_t) sys_mmap (sys_arg (int, 1), sys_arg (void *, 2));
				break;
			case SYS_MUNMAP:
				sys_munmap (sys_arg (mapid_t, 1));
				break;
			case SYS_CHDIR:
				f->eax = (uint32_t)sys_chdir(sys_arg(char *,1));
				break;
			case SYS_MKDIR:
				f->eax = (uint32_t)sys_mkdir(sys_arg(char *,1));
				break;
			case SYS_READDIR:
				f->eax = (uint32_t)sys_readdir(sys_arg(int, 1),sys_arg(char *,2));
				break;
			case SYS_ISDIR:
				f->eax = (uint32_t)sys_isdir(sys_arg(int,1));
				break;
			case SYS_INUMBER:
				f->eax = (uint32_t)sys_inumber(sys_arg(int,1));
				break;
			default:
				break;
		}
	return;
}

static void
sys_halt (void)
{
	shutdown_power_off ();
}

static void
sys_exit (int status)
{

	struct thread *cur ;
	enum intr_level old_level;

	cur = thread_current ();
	cur->process_status = status;
	
	old_level = intr_disable ();
	if (cur->parent != NULL)
		{
			cur->elem_in_parent->status = status;
		}
	intr_set_level (old_level);

	thread_exit ();
}

static pid_t
sys_exec (const char *cmd_line)
{
	validate_str (cmd_line, PGSIZE);
	tid_t t = process_execute (cmd_line);
	return t;
}

static int
sys_wait (pid_t pid)
{
	return process_wait ((tid_t) pid);
}

static bool
sys_create (const char *file_name, unsigned initial_size)
{
	validate_str (file_name, PGSIZE);
	bool success;
	success = filesys_create (file_name, initial_size);
	return success;
}

static bool
sys_remove (const char *file_name)
{
	validate_str (file_name, PGSIZE);
	bool success;
	success = filesys_remove (file_name);
	return success;
}

static int
sys_open (const char *file_name)
{
	validate_str (file_name, PGSIZE);
	struct file *file;
	int fd;
	file = filesys_open (file_name);
	if ((file != NULL) && ((fd = get_next_fd ()) != FD_ERROR))
		{
			struct fd_file *fd_file = 
						(struct fd_file *) malloc (sizeof (struct fd_file));
			if (fd_file == NULL)
				{
					file_close (file);
					return FD_ERROR;
				}
			fd_file->fd = fd;
			fd_file->file = file;
			struct thread *cur = thread_current ();
			list_push_front (&cur->open_files, &fd_file->elem);
		}
	else
		{
			file_close (file);
			return FD_ERROR;
		}
	return fd;
}

static int
sys_filesize (int fd)
{
	struct file *file = lookup_fd (fd);
	
	if (file == NULL)
		return -1;

	int file_size;
	file_size = file_length (file);

	return file_size;
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
	int read_count = 0;
	struct file *file;
	uint8_t *trusted_buffer = NULL;
	
	if (size > 0)
		{
			trusted_buffer = (uint8_t *) malloc (size);
			if (trusted_buffer == NULL)
				return -1;
		}
		
	if (fd == STDIN_FILENO)
		{
			uint8_t in_char;
			for (read_count = 0; (unsigned) read_count < size; read_count++)
				{
					in_char = input_getc ();
					if (in_char == (uint8_t) END_OF_TEXT)
						break;
					trusted_buffer[read_count] = in_char;
				}
		}
	else
		{
			if ((file = lookup_fd (fd)) != NULL)
				{
					read_count = file_read (file, trusted_buffer, size);
				}
			else
				{
					read_count = -1;
				}
		}

	if (write_buffer (buffer, trusted_buffer, read_count) == false)
		{
			if (trusted_buffer != NULL)
				free (trusted_buffer);
			thread_exit ();
		}
	else
		{
			if (trusted_buffer != NULL)
				free (trusted_buffer);
			return read_count;
		}

}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
	int write_count = 0;
	struct file *file;
	uint8_t *trusted_buffer = NULL;

	if (size > 0)
		{
			trusted_buffer = (uint8_t *) malloc (size);
			if (trusted_buffer == NULL)
				return -1;
		}

	if (read_buffer (trusted_buffer, buffer, size) == false)
		{
			if (trusted_buffer != NULL) 
				free (trusted_buffer);
			thread_exit ();
		}
	
	if (fd == STDOUT_FILENO)
		{
			while (size > CONSOLE_CHUNK_SIZE)
				{
					putbuf (buffer, CONSOLE_CHUNK_SIZE);
					size -= CONSOLE_CHUNK_SIZE;
					write_count += CONSOLE_CHUNK_SIZE;
					buffer += CONSOLE_CHUNK_SIZE;
				}
			putbuf (buffer, size);
			write_count += size;
		}
	else
		{
			if ((file = lookup_fd (fd)) != NULL)
				{
					write_count = file_write (file, trusted_buffer, size);
				}
			else
				{
					write_count = -1;
				}
		}
	if (trusted_buffer != NULL)
		free (trusted_buffer);
	return write_count;
}

static void
sys_seek (int fd, unsigned position)
{
	struct file* file = lookup_fd (fd);
	if (file != NULL)
		{
			file_seek (file, position);
		} 
}

static unsigned
sys_tell (int fd)
{
	struct file* file = lookup_fd (fd);
	if (file != NULL)
		{
			return file_tell (file);
		} 
	return -1;
}

static void
sys_close (int fd)
{
	struct thread *cur = thread_current ();
	struct list_elem *e;
	for (e = list_begin (&cur->open_files); e != list_end (&cur->open_files);
			 e = list_next (e))
		{
			struct fd_file *fd_file = list_entry (e, struct fd_file, elem);
			if (fd_file->fd == fd)
				{
					list_remove (e);
					file_close (fd_file->file);
					free (fd_file);
				}
			break;
		}
}

static mapid_t
sys_mmap (int fd, void *addr)
{
	if (pg_ofs (addr) != 0)
		return MAP_FAILED;
	if (addr == 0)
		return MAP_FAILED;
	struct file *file = lookup_fd (fd);
	if (file == NULL)
		return MAP_FAILED;

	file = file_reopen (file);

	off_t read_bytes = file_length (file);

	uint32_t range_start = (uint32_t) addr;
	uint32_t range_end = (uint32_t) addr + (uint32_t) read_bytes;
	range_end = (uint32_t) pg_round_up ((void *)range_end);
	if (range_end >= (uint32_t) PHYS_BASE)
		{
			file_close (file);
			return MAP_FAILED;
		}
		
	struct thread *t = thread_current ();
	lock_acquire(&t->spt_lock);
	struct hash_iterator i;
	hash_first (&i, &t->mpage_hash);
	while (hash_next (&i))
		{ 
			struct mpage_entry *mpte = hash_entry (hash_cur (&i), 
					struct mpage_entry, elem);
			if (((uint32_t) mpte->uaddr < range_end) && 
				((uint32_t) mpte->uaddr + PGSIZE > range_start))
				{
					file_close (file);
					lock_release(&t->spt_lock);
					return MAP_FAILED;
				}	
		}
	lock_release(&t->spt_lock);
	/* valid */
	struct mmap_entry *mm_entry = (struct mmap_entry *)
			malloc (sizeof (struct mmap_entry));
	mm_entry->file = file;
	mm_entry->mid = get_next_mid();
	mm_entry->size = read_bytes;
	mm_entry->vaddr = addr;
	if (mm_entry->mid == MAP_FAILED)
		{
			file_close (file);
			free (mm_entry);
			return MAP_FAILED;
		}
	size_t page_cnt = DIV_ROUND_UP (read_bytes, PGSIZE);
	if(!load_segment_lazy (file, 0, addr, read_bytes, 
							PGSIZE * page_cnt-read_bytes, TYPE_FILE)) 
		{
			free(mm_entry);
			file_close (file);
			return MAP_FAILED;
		}
	list_push_back (&t->mmap_list, &mm_entry->elem);
	return mm_entry->mid;
}

static void
sys_munmap (mapid_t mapid)
{
	struct mmap_entry *mm_entry = lookup_mid (mapid);
	if (mm_entry == NULL) 
		return;
	struct thread *cur = thread_current ();
	lock_acquire(&cur->spt_lock);
	struct hash *mpage_hash = &cur -> mpage_hash;
	void *vaddr = mm_entry->vaddr;
	size_t size = mm_entry->size;
	while(size > 0)
		{
			struct mpage_entry *mpte = mpage_lookup (mpage_hash, vaddr); 
			ASSERT(mpte != NULL);
			if (frame_exist_and_pin (mpte)) 
				{
					if (frame_check_dirty (mpte->uaddr, mpte->fte->paddr))
						{
							file_write_at (mpte->file, mpte->uaddr, mpte->length, mpte->ofs);
						}
					frame_free_frame (mpte->fte->paddr);
					pagedir_clear_page (cur->pagedir, mpte->uaddr);
				}
			hash_delete (&cur->mpage_hash, &mpte->elem);
			vaddr += mpte->length;
			size-=mpte->length;
			free (mpte);
		}
	lock_release(&cur->spt_lock);
	list_remove (&mm_entry->elem);
	file_close (mm_entry->file);
	free (mm_entry);
	return;
}

static bool 
sys_chdir (const char *dir)
{
	validate_str (dir, PGSIZE);
	struct dir *dir_path;
	char target_dir[NAME_MAX + 1];

	if (!dir_parser (&dir_path, target_dir, dir))
		return false;

	struct inode *inode = NULL;
	if(!dir_lookup (dir_path, target_dir, &inode)){
		dir_close(dir_path);
	 	return false;
	}
	
	if(!inode_is_dir(inode)){
	dir_close(dir_path);
	return false;
	}
	dir_close(dir_path);
	struct dir *target = dir_open(inode);
	if(target==NULL) return false;
	dir_close(thread_current()->cur_dir);
	thread_current()->cur_dir = target;
	return true;
}

static bool sys_mkdir(const char *dir){
	char target_dir[NAME_MAX+1];
  struct dir *dir_path;
  if(!dir_parser(&dir_path,target_dir,dir))
   return false; 
  struct inode *inode=NULL;
  block_sector_t sector=0;
  if(!free_map_allocate(1,&sector)){
    dir_close(dir_path);
    return false;
  }
  if(!dir_create(sector,2)){
    free_map_release(sector,1);
    dir_close(dir_path);
    return false;
  }
   inode = inode_open(sector);
   struct dir *new_dir = dir_open(inode);
   if(new_dir==NULL){
   inode_remove(inode);
   inode_close(inode);
   dir_close(dir_path);
   return false;
   }

   bool   success = dir_add(dir_path,target_dir,sector) && dir_add(new_dir,".",sector) && dir_add(new_dir,"..",inode_get_inumber(dir_get_inode(dir_path)));
  
  if(!success){
    inode_remove(inode);
    }
    dir_close(new_dir);
    dir_close(dir_path);
   return success;
}


static bool sys_readdir(int fd, char *name){
   struct file *file = lookup_fd(fd);
   if(file==NULL)
    return false;
    struct inode *inode = file_get_inode(file);
   if(!inode_is_dir(inode))
    return false;
   struct dir *dir = dir_open(inode_reopen(inode));
   if(dir==NULL)
    return false;
   dir_set_pos(dir,file_tell(file));
   while(dir_readdir(dir,name)){
    file_seek(file,dir_get_pos(dir));
    if(strcmp(name,".") && strcmp(name,".."))
    {
    	dir_close (dir);
    	return true;
    }
   } 
   dir_close(dir);
   return false;
}
static bool sys_isdir(int fd){
   struct file *file = lookup_fd(fd);
   if(file==NULL)
   return false;
   struct inode *inode = file_get_inode(file);
   if(inode == NULL)
   return false;
   return inode_is_dir(inode);
}

static int sys_inumber(int fd){
  struct file *file = lookup_fd(fd);
   if(file==NULL)
   return false;
   struct inode *inode = file_get_inode(file);
   if(inode == NULL)
   return false;
   return inode_get_inumber(inode);
}

static void
validate_str (const char *str, int max_len)
{
	int i;
	int result;
	for (i = 0; i < max_len; str++)
		{
			if ((unsigned)str >= (unsigned)PHYS_BASE)
				thread_exit ();
			result = get_user ((uint8_t *)str);
			if (result == -1)
				thread_exit ();
			if (result == '\0')
				return;
		}
	thread_exit ();
}

static mapid_t
get_next_mid ()
{
	struct thread *cur = thread_current ();
	int mid;
	if ((mid = cur->next_mid) == MAP_MAX)
		return MAP_FAILED;
	else
		{
			cur->next_mid += 1;
			return mid;
		}
}

static int
get_next_fd ()
{
	struct thread *cur = thread_current ();
	int fd;
	if ((fd = cur->next_fd) == FD_MAX)
		return FD_ERROR;
	else
		{
			cur->next_fd += 1;
			return fd;
		}
}

static struct file *
lookup_fd (int fd)
{
	struct thread *cur = thread_current ();
	struct list_elem *e;
	for (e = list_begin (&cur->open_files); e != list_end (&cur->open_files);
			 e = list_next (e))
		{
			struct fd_file *fd_file = list_entry (e, struct fd_file, elem);
			if (fd_file->fd == fd)
				{
					return fd_file->file;
				}
		}
	return NULL;
}

static struct mmap_entry *
lookup_mid (mapid_t mid)
{
	struct thread *cur = thread_current ();
	struct list_elem *e;
	for (e = list_begin (&cur->mmap_list); e != list_end (&cur->mmap_list);
		 e = list_next (e))
		{
			struct mmap_entry *m = list_entry (e, struct mmap_entry, elem);
			if (m->mid == mid)
				{
					return m;
				}
		}
	return NULL;
}

static int
get_user (const uint8_t *uaddr)
{
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:"
			 : "=&a" (result) : "m" (*uaddr));
	return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte)
{
	int error_code;
	asm ("movl $1f, %0; movb %b2, %1; 1:"
			 : "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

/*
 * read from buffer SRC to a trusted buffer DST.
 * validation is performed on SRC buffer, and if 
 * page fault happens, return false; if succeed, return
 * true;
 */
static bool
read_buffer (uint8_t *dst, const uint8_t *src, int size)
{
	int i;
	int read_byte;
	if (((unsigned) src + size) > (unsigned) PHYS_BASE)
		{
			return false;
		}
	for (i = 0; i < size; i++)
		{
			if ((read_byte = get_user (src++)) == -1)
				{
					return false;
				}
			*dst++ = (uint8_t) read_byte;
		}
	return true;
}

static bool
write_buffer (uint8_t *dst, const uint8_t *src, int size)
{
	int i;
	bool write_result;
	if (((unsigned) dst + size) > (unsigned) PHYS_BASE)
		{
			return false;
		}
	for (i = 0; i < size; i++)
		{
			if ((write_result = put_user (dst++, *src++)) == false)
				{
					return false;
				}
		}
	return true;
}

static uint32_t
validate_and_read_arg (uint32_t *uaddr)
{
	unsigned i; 
	int read_byte;

	if ((unsigned) uaddr >= (unsigned) PHYS_BASE)
	{
		thread_exit ();
	}

	for (i = 0; i < (sizeof (uint32_t) / sizeof (uint8_t)); i++)
		{
			if ((read_byte = get_user (((uint8_t *)uaddr) + i)) == -1)
				{
					thread_exit ();
				}
		}
	return *uaddr;
}


