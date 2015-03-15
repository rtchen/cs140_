#ifndef VM_MPAGE_H
#define VM_MPAGE_H

#include <hash.h>
#include <debug.h>
#include <list.h>
#include <stddef.h>
#include "devices/block.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "threads/synch.h"
#include "vm/frame.h"

enum page_type
	{
		TYPE_ZERO,
		TYPE_STACK,
		TYPE_LOADING,
		TYPE_LOADING_WRITABLE,
		TYPE_LOADED_WRITABLE,
		TYPE_FILE
	};

struct mpage_entry
	{
		void *uaddr;
		enum page_type type;
		struct frame_entry *fte;

		size_t swap_sector;
		struct file *file;
		off_t ofs;
		uint32_t length;

		struct hash_elem elem;
		struct list_elem list_elem;
	};

void mpage_init (struct hash *mpage_hash,struct lock *lock);
struct mpage_entry *mpage_lookup (struct hash *mpage_hash, void *uaddr);
hash_action_func print_mpte;

#endif
