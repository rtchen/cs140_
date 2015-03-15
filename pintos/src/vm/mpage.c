#include "vm/mpage.h"

#include <hash.h>
#include <stdlib.h>
#include <stdio.h>
#include <debug.h>

static bool mpage_func_less 
	(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

static unsigned mpage_func_hash 
	(const struct hash_elem *p_, void *aux UNUSED);

void
mpage_init (struct hash *mpage_hash,struct lock *lock)
{
  lock_init(lock);
	hash_init (mpage_hash, mpage_func_hash, mpage_func_less, NULL);
}

void
print_mpte (struct hash_elem *e, void *aux UNUSED)
{
	struct mpage_entry *mpte =
	hash_entry (e, struct mpage_entry, elem);
	printf ("[mpage] uaddr:%p,\
						type:%d,\
						fte:%p, swap_sector: %u,\
						file:%p, ofs:%u,\
						length:%u\n", 
						mpte->uaddr, 
						mpte->type, 
						mpte->fte, 
						mpte->swap_sector, 
						mpte->file, 
						mpte->ofs, 
						mpte->length);
}

struct mpage_entry *
mpage_lookup (struct hash *mpage_hash, void *uaddr)
{
	struct mpage_entry m;
	struct hash_elem *e;
	m.uaddr = uaddr;
	e = hash_find (mpage_hash, &m.elem);
	return (e != NULL) ? hash_entry (e, struct mpage_entry, elem) : NULL;
}

static bool 
mpage_func_less (const struct hash_elem *a_, const struct hash_elem *b_,
						void *aux UNUSED)
{
	const struct mpage_entry *a = 
		hash_entry (a_, struct mpage_entry, elem);
	const struct mpage_entry *b =
		hash_entry (b_, struct mpage_entry, elem);
	return a->uaddr < b->uaddr;
}

static unsigned
mpage_func_hash (const struct hash_elem *p_, void *aux UNUSED)
{
	const struct mpage_entry *p =
		hash_entry (p_, struct mpage_entry, elem);
	return hash_bytes (&p->uaddr, sizeof p->uaddr);
}
