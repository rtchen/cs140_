#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <user/syscall.h>
#include "vm/mmap.h"

void syscall_init (void);

void syscall_munmap (struct mmap_entry *mm_entry);

#endif /* userprog/syscall.h */
