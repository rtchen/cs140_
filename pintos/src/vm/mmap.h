#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <list.h>
#include "filesys/file.h"

typedef int mapid_t;

#define MAP_FAILED ((mapid_t) -1)
#define MAP_MAX 32767

struct mmap_entry
{
	mapid_t mid;
	struct file *file;
	void *vaddr;
    size_t size;
	struct list_elem elem;
};

#endif
