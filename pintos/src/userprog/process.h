#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <inttypes.h>
#include <stdlib.h>
#include "threads/thread.h"
#include "filesys/file.h"
#include "vm/mpage.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool load_segment_lazy (struct file *file, off_t ofs, uint8_t *upage,
   		uint32_t read_bytes, uint32_t zero_bytes, enum page_type type);

struct child_process
{
	tid_t tid;
	int status;
	struct thread *thread;
	struct semaphore wait_sema;
	struct list_elem elem;
};

struct fd_file
{
	int fd;
	struct file *file;
	struct list_elem elem;
};

#endif /* userprog/process.h */

