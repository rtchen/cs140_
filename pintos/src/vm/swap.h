#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include "threads/synch.h"

#define SWAP_ERROR BITMAP_ERROR

struct lock swap_lock;
struct lock swap_disk_lock;

void swap_init (void);
size_t swap_find_free_slot (void);
void swap_set_slot (size_t idx);
void swap_reset_slot (size_t idx);
void swap_read_slot (size_t idx, void *buffer);
void swap_write_slot (size_t idx, void *buffer);

#endif