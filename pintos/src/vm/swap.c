#include "vm/swap.h"

#include <bitmap.h>
#include <stdio.h>
#include <inttypes.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/block.h"

static struct bitmap *swap_bitmap;
static struct block *swap_block;

#define SCALE (PGSIZE / BLOCK_SECTOR_SIZE)

void
swap_init (void)
{
	lock_init (&swap_lock);
	lock_init (&swap_disk_lock);
	swap_block = block_get_role (BLOCK_SWAP);
	block_sector_t b_size = block_size (swap_block);
	swap_bitmap = bitmap_create (b_size / SCALE);
}

size_t 
swap_find_free_slot (void)
{
	return bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
}

void 
swap_set_slot (size_t idx)
{
	bitmap_mark (swap_bitmap, idx);
}

void 
swap_reset_slot (size_t idx)
{
	bitmap_reset (swap_bitmap, idx);
}

void 
swap_read_slot (size_t idx, void *buffer)
{ 
	int i;
	for (i = 0; i < SCALE; i++)
		{
			block_read (swap_block, SCALE * idx + i, buffer);
			buffer = (void *)((unsigned) buffer + BLOCK_SECTOR_SIZE);
		}
}

void 
swap_write_slot (size_t idx, void *buffer)
{
	int i;
	for (i = 0; i < SCALE; i++)
		{
			block_write (swap_block, SCALE * idx + i, buffer);
			buffer = (void *)((unsigned) buffer + BLOCK_SECTOR_SIZE);
		}
}

