#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#define BUFFER_CACHE_SIZE 64+1	
/* additional sector for keeping free map bitmap sector in memory */

#include <stdbool.h>
#include "threads/synch.h"
#include "devices/block.h"
#include <kernel/bitmap.h>

struct lock bc_lock;

struct bc_entry {
	int sector;
	/* all below protected by shared_lock sl */
	bool access;
	bool dirty;
	struct shared_lock sl;
	char data[BLOCK_SECTOR_SIZE];
};

struct bc_entry cache[BUFFER_CACHE_SIZE];

void cache_init (void);
void * cache_open_read (block_sector_t);
void * cache_create_write (block_sector_t);
void * cache_open_write (block_sector_t);
void cache_close_read (block_sector_t);
void cache_close_write (block_sector_t);
void cache_flush (void);

#endif