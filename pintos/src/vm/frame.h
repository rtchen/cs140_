#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <stdlib.h>
#include "vm/mpage.h"
#include "vm/mpage.h"
#include "threads/thread.h"

struct list frame_list;

struct frame_entry
	{
		void *paddr;
		struct thread *t;
		struct mpage_entry *mpte;
		bool pinned;
		struct list_elem elem;
	};

void frame_init (void);
struct frame_entry *frame_get_frame_pinned (bool zero);
void frame_unpin_frame (void *paddr);
void frame_free_frame (void *paddr);

bool frame_exist_and_pin (struct mpage_entry *mpte);
bool frame_exist_and_free (struct mpage_entry *mpte);

bool frame_check_dirty (void *uaddr, void *paddr);
void frame_clean_dirty (void *uaddr, void *paddr);

#endif