#include "filesys/cache.h"

#include "filesys/filesys.h"
#include "threads/synch.h"
#include <stdbool.h>
#include <debug.h>
#include <stdio.h>
#include "devices/timer.h"
#include "threads/thread.h"
#include <string.h>

#define FILESYS_CACHE_DEBUG

static int clock_hand;
static int cache_find_cached_sector (block_sector_t sector);
static thread_func cache_write_behind;
static void * cache_open (block_sector_t sector, bool write, bool create);

void
cache_init ()
{
	int i;

	clock_hand = 0;
	lock_init (&bc_lock);
	
	for (i = 0; i < BUFFER_CACHE_SIZE; i++)
	{
		struct bc_entry *e = &(cache[i]);
		e->sector = -1;
		e->access = false;
		e->dirty = false;
		shared_lock_init (&e->sl);
	}
	thread_create ("cache_wb", 0, cache_write_behind, NULL);
}

void 
cache_flush ()
{
	int i;
	for (i = 0; i < BUFFER_CACHE_SIZE; i++)
	{
		shared_lock_acquire_read (&cache[i].sl);
		if (cache[i].sector != -1)
		{
			block_write (fs_device, cache[i].sector, (void *) cache[i].data);
			cache[i].dirty = false;
		}
		shared_lock_release_read (&cache[i].sl);
	}
}

void *
cache_open_read (block_sector_t sector)
{
	return cache_open (sector, false, false);
}

void *
cache_open_write (block_sector_t sector)
{
	return cache_open (sector, true, false);
}

void *
cache_create_write (block_sector_t sector)
{
	return cache_open (sector, true, true);
}

void 
cache_close_read (block_sector_t sector)
{
	lock_acquire (&bc_lock);
	int idx = cache_find_cached_sector (sector);

	ASSERT (idx >= 0);

	shared_lock_release_read (&cache[idx].sl);
	lock_release (&bc_lock);
}

void 
cache_close_write (block_sector_t sector)
{
	lock_acquire (&bc_lock);
	int idx = cache_find_cached_sector (sector);

	ASSERT (idx >= 0);

	shared_lock_release_write (&cache[idx].sl);
	lock_release (&bc_lock);
}

static int
cache_find_cached_sector (block_sector_t sector)
{
	ASSERT (lock_held_by_current_thread (&bc_lock));
	int idx;
	for (idx = 0; idx < BUFFER_CACHE_SIZE; idx++)
	{
		if (cache[idx].sector == sector)
			return idx;
	}
	return -1;
}

static void
cache_write_behind (void *aux)
{
	while (true)
	{
		int i;
		for (i = 0; i < BUFFER_CACHE_SIZE; i++)
		{
			shared_lock_acquire_read (&cache[i].sl);
			if ((cache[i].sector != -1) && (cache[i].dirty == true))
			{
				block_write (fs_device, cache[i].sector, (void *) cache[i].data);
				cache[i].dirty = false;
			}
			shared_lock_release_read (&cache[i].sl);
		}
		/* 1000 times per minute */
		timer_msleep (60);
	}
}

static void *
cache_open (block_sector_t sector, bool write, bool create)
{
	ASSERT (!(write == false && create == true));
	lock_acquire (&bc_lock);
	int idx = cache_find_cached_sector (sector);
	if (create)
	{
		ASSERT (idx == -1);
	}
        if (idx >= 0) 
	{
		if (write)
			shared_lock_acquire_write (&cache[idx].sl);
		else
			shared_lock_acquire_read (&cache[idx].sl);
		lock_release (&bc_lock);
		cache[idx].access = true;
		if (write)
			cache[idx].dirty = true;
		return (void *)cache[idx].data;
	}
	for (idx = 0; idx < BUFFER_CACHE_SIZE; idx++)
	{
		struct bc_entry *e = &cache[idx];
		if (e->sector == -1 && shared_lock_try_acquire_write (&e->sl))
		{
			e->sector = sector;
			e->access = true;
			e->dirty = write;
			lock_release (&bc_lock);
			block_read (fs_device, sector, (void *) e->data);
			if (!write)
				shared_lock_downgrade_write_to_read (&e->sl);
			return (void *) e->data;
		}
	}
	while (true)
	{
		struct bc_entry *e = &cache[clock_hand];
		/* never evict the FREE_MAP_SECTOR */
		if (e->sector == FREE_MAP_SECTOR)
		{
			clock_hand = (clock_hand + 1) % BUFFER_CACHE_SIZE;
			continue;
		}
		if (e->access == true)
		{
			e->access = false;
			clock_hand = (clock_hand + 1) % BUFFER_CACHE_SIZE;
		}
		else if (!shared_lock_try_acquire_write(&e->sl))
		{
			clock_hand = (clock_hand + 1) % BUFFER_CACHE_SIZE;
		}
		else
		{
			block_sector_t old_sector = e->sector;
			e->sector = sector;
			clock_hand = (clock_hand + 1) % BUFFER_CACHE_SIZE;

			if (e->dirty)
			{
				block_write (fs_device, old_sector, (void *) e->data);
			}
			/* must wait for write back to complete and then release bc_lock */
			lock_release (&bc_lock);
			e->access = true;
			e->dirty = write;
			if (create)
			{
				static char zeros[BLOCK_SECTOR_SIZE];
				memcpy ((void *) e->data, &zeros, BLOCK_SECTOR_SIZE);
			}
			else
			{
				block_read (fs_device, sector, (void *) e->data);
			}
			if (!write)
				shared_lock_downgrade_write_to_read (&e->sl);
			return (void *) e->data;
		}
	}
}
