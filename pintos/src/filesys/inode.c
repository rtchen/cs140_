#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_CNT 16
#define INDIRECT_CNT 16
#define DOUBLY_INDIRECT_CNT 1
#define ENTRY_CNT (BLOCK_SECTOR_SIZE/4)

static struct lock inode_lock;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  unsigned int directory;             /* direct or not */
  off_t length;                       /* File size in bytes. */
  block_sector_t direct[DIRECT_CNT];
  block_sector_t indirect[INDIRECT_CNT];
  block_sector_t doubly[DOUBLY_INDIRECT_CNT];
  unsigned magic;                     /* Magic number. */
  uint32_t unused[92];               /* Not used. */
};

struct indirect_disk
{
  block_sector_t direct[128];
};

struct doubly_disk
{
  block_sector_t indirect[128];
};

struct inode_index
{
  int doubly;
  int indirect;
  int direct; 
};

struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock dir_lock;
    struct lock extend_lock;
 };

static bool inode_inflate_sectors (block_sector_t sector, size_t sectors);
static bool inode_inflate_a_sector (block_sector_t sector, struct inode_index idx);

static void
index_from_sector (struct inode_index *idx, size_t sector)
{
  if (sector < DIRECT_CNT)
  {
    idx->doubly = -1;
    idx->indirect = -1;
    idx->direct = sector;
    return;
  }
  else if (sector < DIRECT_CNT + INDIRECT_CNT * ENTRY_CNT)
  {
    sector = sector - DIRECT_CNT;
    idx->doubly = -1;
    idx->indirect = sector / ENTRY_CNT;
    idx->direct = sector % ENTRY_CNT;
    return;
  }
  else if (sector < DIRECT_CNT + INDIRECT_CNT * ENTRY_CNT + DOUBLY_INDIRECT_CNT * ENTRY_CNT * ENTRY_CNT)
  {
    sector = sector - DIRECT_CNT - INDIRECT_CNT * ENTRY_CNT;
    idx->doubly = sector / ENTRY_CNT / ENTRY_CNT;
    sector = sector % (ENTRY_CNT * ENTRY_CNT);
    idx->indirect = sector / ENTRY_CNT;
    idx->direct = sector % ENTRY_CNT;
    return;
  }
  NOT_REACHED ();
}

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  size_t sectors = pos / BLOCK_SECTOR_SIZE;
  struct inode_index idx;
  index_from_sector (&idx, sectors);

  block_sector_t sector = inode->sector;
  struct inode_disk *disk_inode;
  struct indirect_disk *disk_indirect;
  struct doubly_disk *disk_doubly;

  int result;

  if ((idx.doubly == -1) && (idx.indirect == -1))
  {
    disk_inode = (struct inode_disk *) cache_open_read (sector);
    block_sector_t direct_sector = disk_inode->direct[idx.direct];
    cache_close_read (sector);
    result = direct_sector;
  }
  else if (idx.doubly == -1)
  {
    disk_inode = (struct inode_disk *) cache_open_read (sector);
    block_sector_t indirect_sector = disk_inode->indirect[idx.indirect];
    cache_close_read (sector);
    ASSERT (indirect_sector != 0);
    disk_indirect = (struct indirect_disk *) cache_open_read (indirect_sector);
    block_sector_t direct_sector = disk_indirect->direct[idx.direct];
    cache_close_read (indirect_sector);
    result = direct_sector;
  }
  else
  {
    disk_inode = (struct inode_disk *) cache_open_read (sector);
    block_sector_t doubly_sector = disk_inode->doubly[idx.doubly];
    cache_close_read (sector);
    ASSERT (doubly_sector != 0);
    disk_doubly = (struct doubly_disk *) cache_open_read (doubly_sector);
    block_sector_t indirect_sector = disk_doubly->indirect[idx.indirect];
    cache_close_read(sector);
    ASSERT (indirect_sector != 0);
    disk_indirect = (struct indirect_disk *) cache_open_read (indirect_sector);
    block_sector_t direct_sector = disk_indirect->direct[idx.direct];
    cache_close_read (indirect_sector);
    result = direct_sector;
  }
  return result;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&inode_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;

  ASSERT (length >= 0);
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  size_t sectors = bytes_to_sectors (length);

  disk_inode = (struct inode_disk *) cache_create_write (sector);
  disk_inode->directory = is_dir ? 1 : 0;
  disk_inode->length = length;
  disk_inode->magic = INODE_MAGIC;
  cache_close_write (sector);

  bool success = inode_inflate_sectors (sector, sectors);
  return success;
}

/* returns a `struct inode' that links to SECTOR.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  //printf ("inode_open, sector: %d\n", sector);
  lock_acquire (&inode_lock);

  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          lock_release (&inode_lock);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
  {
    lock_release (&inode_lock);
    return NULL;
  }
  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->dir_lock);
  lock_init (&inode->extend_lock);
  lock_release (&inode_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  //printf ("inode_reopen, sector: %d\n", inode->sector);
  if (!lock_held_by_current_thread (&inode_lock))
  {
    lock_acquire (&inode_lock);
    if (inode != NULL)
      inode->open_cnt++;
    lock_release (&inode_lock);
    return inode;
  }
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  //printf ("inode_get_inumber, sector: %d\n", inode->sector);
  lock_acquire (&inode_lock);
  block_sector_t sector = inode->sector;
  lock_release (&inode_lock);
  return sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  //printf ("inode_close, sector: %d\n", inode->sector);
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire (&inode_lock);
  int open_cnt = --inode->open_cnt;
  if (open_cnt != 0) {
    lock_release (&inode_lock);
    return;
  }
  /* Release resources if this was the last opener. */
  if (open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
      lock_release (&inode_lock);
      /* Deallocate blocks if removed. */
      block_sector_t sector = inode->sector;
      bool removed = inode->removed;
      free (inode);
      if (removed) 
        {
          // release all mapping
          int i;
          struct inode_disk *disk_inode = NULL;
          struct indirect_disk *disk_indirect = NULL;
          struct doubly_disk *disk_doubly = NULL;

          for (i = 0; i < DIRECT_CNT; i++)
          {
            disk_inode = (struct inode_disk *) cache_open_write (sector);
            block_sector_t direct_sector = disk_inode->direct[i];
            cache_close_write (sector);
            if (direct_sector == 0)
            {
              free_map_release (sector, 1);
              return;
            }
            free_map_release (direct_sector, 1);
          }
          for (i = 0; i < INDIRECT_CNT; i++)
          {
            disk_inode = (struct inode_disk *) cache_open_write (sector);
            block_sector_t indirect_sector = disk_inode->indirect[i];
            cache_close_write (sector);
            if (indirect_sector == 0)
            {
              free_map_release (sector, 1);
              return;
            }
            int j;
            for (j = 0; j < ENTRY_CNT; j++)
            {
              disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
              block_sector_t direct_sector = disk_indirect->direct[j];
              cache_close_write (indirect_sector);
              if (direct_sector == 0)
              {
                free_map_release (indirect_sector, 1);
                free_map_release (sector, 1);
                return;
              }
              free_map_release (direct_sector, 1);
            }
            free_map_release (indirect_sector, 1);
          }
          for (i = 0; i < DOUBLY_INDIRECT_CNT; i++)
          {
            disk_inode = (struct inode_disk *) cache_open_write (sector);
            block_sector_t doubly_sector = disk_inode->doubly[i];
            cache_close_write (sector);
            if (doubly_sector == 0)
            {
              free_map_release (sector, 1);
              return;
            }
            int j;
            for (j = 0; j < ENTRY_CNT; j++)
            {
              disk_doubly = (struct doubly_disk *) cache_open_write (doubly_sector);
              block_sector_t indirect_sector = disk_doubly->indirect[j];
              cache_close_write (doubly_sector);
              if (indirect_sector == 0)
              {
                free_map_release (doubly_sector, 1);
                free_map_release (sector, 1);
                return;
              }
              int k;
              for (k = 0; k < ENTRY_CNT; k++)
              {
                disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
                block_sector_t direct_sector = disk_indirect->direct[k];
                cache_close_write (indirect_sector);
                if (direct_sector == 0)
                {
                  free_map_release (indirect_sector, 1);
                  free_map_release (doubly_sector, 1);
                  free_map_release (sector, 1);
                  return;
                }
                free_map_release (direct_sector, 1);
              }
              free_map_release (indirect_sector, 1);
            }
            free_map_release (doubly_sector, 1);
          }
          free_map_release (sector, 1);
        }
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  //printf ("inode_remove, sector: %d\n", inode->sector);
  ASSERT (inode != NULL);
  lock_acquire (&inode_lock);
  inode->removed = true;
  lock_release (&inode_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  //printf ("inode_read_at\n");
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *data = NULL;

  off_t length = inode_length (inode);
  
  if (offset >= length)
    return 0;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = length - offset;
      ASSERT (inode_left >= 0);
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          data = (uint8_t *) cache_open_read (sector_idx);
          memcpy (buffer + bytes_read, data, BLOCK_SECTOR_SIZE);
          cache_close_read (sector_idx);
        }
      else 
        {
          data = (uint8_t *) cache_open_read (sector_idx);
          memcpy (buffer + bytes_read, data + sector_ofs, chunk_size);
          cache_close_read (sector_idx);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  //printf ("inode_write_at; sector:%d, size:%d\n", inode->sector, size);
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *data = NULL;

  if (inode->deny_write_cnt)
    return 0;

  off_t length = inode_length (inode);

  if (length < offset + size)
  {
    // printf ("file extending..., with offset: %d, size: %d\n", offset, size);
    lock_acquire (&inode->extend_lock);
    // make sure really needs to extend
    length = inode_length (inode);
    // printf ("length before extending: %d\n", length);
    if (length >= offset + size)
    {
      lock_release (&inode->extend_lock);
    }
    else
    {
      size_t start_sector = bytes_to_sectors (length);
      size_t end_sector = bytes_to_sectors (offset + size);
      // printf ("start_sector: %d, end_sector: %d\n", start_sector, end_sector);
      size_t i;
      struct inode_index idx;
      for (i = start_sector; i < end_sector; i++)
      {
        index_from_sector (&idx, i);
        if (!inode_inflate_a_sector (inode->sector, idx))
          break;
      }
      length = (i + 1) * BLOCK_SECTOR_SIZE;
      if (length > offset + size)
      {
        length = offset + size;
      }
    }
  }
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          data = (uint8_t *) cache_open_write (sector_idx);
          memcpy (data, buffer + bytes_written, BLOCK_SECTOR_SIZE);;
          cache_close_write (sector_idx);
        }
      else 
        {
          data = (uint8_t *) cache_open_write (sector_idx);
          memcpy (data + sector_ofs, buffer + bytes_written, chunk_size);
          cache_close_write (sector_idx);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  if (lock_held_by_current_thread (&inode->extend_lock))
  {
    struct inode_disk *disk_inode = (struct inode_disk *) cache_open_write (inode->sector);
    disk_inode->length = length;
    cache_close_write (inode->sector);
    lock_release (&inode->extend_lock);
  }
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  //printf ("inode_deny_write, sector: %d\n", inode->sector);
  lock_acquire (&inode_lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release (&inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  //printf ("inode_allow_write, sector: %d\n", inode->sector);
  lock_acquire (&inode_lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release (&inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk *disk_inode = (struct inode_disk *) cache_open_read (inode->sector);
  off_t length = disk_inode->length;
  cache_close_read (inode->sector);
  return length;
}

void inode_dir_lock(struct inode *inode){
  lock_acquire(&inode->dir_lock);
}
void inode_dir_unlock(struct inode *inode){
  lock_release(&inode->dir_lock);
}

int inode_get_open_cnt(struct inode *inode){
   return inode->open_cnt;
}
bool inode_is_dir(struct inode *inode){
   struct inode_disk *disk_inode = (struct inode_disk *) cache_open_read (inode->sector);
   bool is_dir = disk_inode->directory;
   cache_close_read (inode->sector);
   return is_dir;
}

static bool
inode_inflate_sectors (block_sector_t sector, size_t sectors)
{
  size_t i;
  struct inode_disk *disk_inode = NULL;
  struct indirect_disk *disk_indirect = NULL;
  struct doubly_disk *disk_doubly = NULL;
  struct inode_index idx;

  for (i = 0; i < sectors; i++)
  {
    index_from_sector (&idx, i);
    if ((idx.doubly == -1) && (idx.indirect == -1))
    {
      // direct block
      disk_inode = (struct inode_disk *) cache_open_write (sector);
      block_sector_t direct_sector = disk_inode->direct[idx.direct];
      cache_close_write (sector);
      if (direct_sector == 0)
      {
        // no direct_sector, create direct sector
        if (!free_map_allocate (1, &direct_sector))
        {
          goto fail;
        }
        disk_inode = (struct inode_disk *) cache_open_write (sector);
        disk_inode->direct[idx.direct] = direct_sector;
        cache_close_write (sector);
        // zero direct_sector
        cache_create_write (direct_sector);
        cache_close_write (direct_sector);
      }
    }
    else if (idx.doubly == -1)
    {
      // indirect block
      disk_inode = (struct inode_disk *) cache_open_write (sector);
      block_sector_t indirect_sector = disk_inode->indirect[idx.indirect];
      cache_close_write (sector);
      if (indirect_sector == 0)
      {
        // no indirect_sector, create indirect sector
        if (!free_map_allocate (1, &indirect_sector))
        {
          goto fail;
        }
        disk_inode = (struct inode_disk *) cache_open_write (sector);
        disk_inode->indirect[idx.indirect] = indirect_sector;
        cache_close_write (sector);
        // zero indirect_sector
        cache_create_write (indirect_sector);
        cache_close_write (indirect_sector);
      }
      // indirect -> direct block
      disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
      block_sector_t direct_sector = disk_indirect->direct[idx.direct];
      cache_close_write (indirect_sector);
      if (direct_sector == 0)
      {
        // no direct_sector, create direct sector
        if (!free_map_allocate (1, &direct_sector))
        {
          goto fail;
        }
        disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
        disk_indirect->direct[idx.direct] = direct_sector;
        cache_close_write (indirect_sector);
        // zero direct_sector
        cache_create_write (direct_sector);
        cache_close_write (direct_sector);
      }
    }
    else
    {
      // doubly block
      disk_inode = (struct inode_disk *) cache_open_write (sector);
      block_sector_t doubly_sector = disk_inode->doubly[idx.doubly];
      cache_close_write (sector);
      if (doubly_sector == 0)
      {
        // no doubly_sector, create doubly_sector sector
        if (!free_map_allocate (1, &doubly_sector))
        {
          goto fail;
        }
        disk_inode = (struct inode_disk *) cache_open_write (sector);
        disk_inode->doubly[idx.doubly] = doubly_sector;
        cache_close_write (sector);
        // zero doubly_sector
        cache_create_write (doubly_sector);
        cache_close_write (doubly_sector);
      }
      // doubly -> indirect block
      disk_doubly = (struct doubly_disk *) cache_open_write (doubly_sector);
      block_sector_t indirect_sector = disk_doubly->indirect[idx.indirect];
      cache_close_write (doubly_sector);
      if (indirect_sector == 0)
      {
        // no indirect_sector, create indirect sector
        if (!free_map_allocate (1, &indirect_sector))
        {
          goto fail;
        }
        disk_doubly = (struct doubly_disk *) cache_open_write (doubly_sector);
        disk_doubly->indirect[idx.indirect] = indirect_sector;
        cache_close_write (doubly_sector);
        // zero indirect_sector
        cache_create_write (indirect_sector);
        cache_close_write (indirect_sector);
      }
      // doubly -> indirect -> direct block
      disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
      block_sector_t direct_sector = disk_indirect->direct[idx.direct];
      cache_close_write (indirect_sector);
      if (direct_sector == 0)
      {
        // no direct_sector, create direct sector
        if (!free_map_allocate (1, &direct_sector))
        {
          goto fail;
        }
        disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
        disk_indirect->direct[idx.direct] = direct_sector;
        cache_close_write (indirect_sector);
        // zero direct_sector
        cache_create_write (direct_sector);
        cache_close_write (direct_sector);
      }
    }
  }
  return true;
fail:
  // release all mapping
  for (i = 0; i < DIRECT_CNT; i++)
  {
    disk_inode = (struct inode_disk *) cache_open_write (sector);
    block_sector_t direct_sector = disk_inode->direct[i];
    cache_close_write (sector);
    if (direct_sector == 0)
      return false;
    free_map_release (direct_sector, 1);
  }
  for (i = 0; i < INDIRECT_CNT; i++)
  {
    disk_inode = (struct inode_disk *) cache_open_write (sector);
    block_sector_t indirect_sector = disk_inode->indirect[i];
    cache_close_write (sector);
    if (indirect_sector == 0)
      return false;
    int j;
    for (j = 0; j < ENTRY_CNT; j++)
    {
      disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
      block_sector_t direct_sector = disk_indirect->direct[j];
      cache_close_write (indirect_sector);
      if (direct_sector == 0)
      {
        free_map_release (indirect_sector, 1);
        return false;
      }
      free_map_release (direct_sector, 1);
    }
    free_map_release (indirect_sector, 1);
  }
  for (i = 0; i < DOUBLY_INDIRECT_CNT; i++)
  {
    disk_inode = (struct inode_disk *) cache_open_write (sector);
    block_sector_t doubly_sector = disk_inode->doubly[i];
    cache_close_write (sector);
    if (doubly_sector == 0)
      return false;
    int j;
    for (j = 0; j < ENTRY_CNT; j++)
    {
      disk_doubly = (struct doubly_disk *) cache_open_write (doubly_sector);
      block_sector_t indirect_sector = disk_doubly->indirect[j];
      cache_close_write (doubly_sector);
      if (indirect_sector == 0)
      {
        free_map_release (doubly_sector, 1);
        return false;
      }
      int k;
      for (k = 0; k < ENTRY_CNT; k++)
      {
        disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
        block_sector_t direct_sector = disk_indirect->direct[k];
        cache_close_write (indirect_sector);
        if (direct_sector == 0)
        {
          free_map_release (indirect_sector, 1);
          free_map_release (doubly_sector, 1);
          return false;
        }
        free_map_release (direct_sector, 1);
      }
      free_map_release (indirect_sector, 1);
    }
    free_map_release (doubly_sector, 1);
  }
  return false;
}

static bool
inode_inflate_a_sector (block_sector_t sector, struct inode_index idx)
{
  struct inode_disk *disk_inode = NULL;
  struct indirect_disk *disk_indirect = NULL;
  struct doubly_disk *disk_doubly = NULL;

  if ((idx.doubly == -1) && (idx.indirect == -1))
  {
    // direct block
    disk_inode = (struct inode_disk *) cache_open_write (sector);
    block_sector_t direct_sector = disk_inode->direct[idx.direct];
    cache_close_write (sector);
    if (direct_sector == 0)
    {
      // no direct_sector, create direct sector
      if (!free_map_allocate (1, &direct_sector))
      {
        goto fail;
      }
      disk_inode = (struct inode_disk *) cache_open_write (sector);
      disk_inode->direct[idx.direct] = direct_sector;
      cache_close_write (sector);
      // zero direct_sector
      cache_create_write (direct_sector);
      cache_close_write (direct_sector);
    }
  }
  else if (idx.doubly == -1)
  {
    // indirect block
    disk_inode = (struct inode_disk *) cache_open_write (sector);
    block_sector_t indirect_sector = disk_inode->indirect[idx.indirect];
    cache_close_write (sector);
    if (indirect_sector == 0)
    {
      // no indirect_sector, create indirect sector
      if (!free_map_allocate (1, &indirect_sector))
      {
        goto fail;
      }
      disk_inode = (struct inode_disk *) cache_open_write (sector);
      disk_inode->indirect[idx.indirect] = indirect_sector;
      cache_close_write (sector);
      // zero indirect_sector
      cache_create_write (indirect_sector);
      cache_close_write (indirect_sector);
    }
    // indirect -> direct block
    disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
    block_sector_t direct_sector = disk_indirect->direct[idx.direct];
    cache_close_write (indirect_sector);
    if (direct_sector == 0)
    {
      // no direct_sector, create direct sector
      if (!free_map_allocate (1, &direct_sector))
      {
        goto fail;
      }
      disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
      disk_indirect->direct[idx.direct] = direct_sector;
      cache_close_write (indirect_sector);
      // zero direct_sector
      cache_create_write (direct_sector);
      cache_close_write (direct_sector);
    }
  }
  else
  {
    // doubly block
    disk_inode = (struct inode_disk *) cache_open_write (sector);
    block_sector_t doubly_sector = disk_inode->doubly[idx.doubly];
    cache_close_write (sector);
    if (doubly_sector == 0)
    {
      // no doubly_sector, create doubly_sector sector
      if (!free_map_allocate (1, &doubly_sector))
      {
        goto fail;
      }
      disk_inode = (struct inode_disk *) cache_open_write (sector);
      disk_inode->doubly[idx.doubly] = doubly_sector;
      cache_close_write (sector);
      // zero doubly_sector
      cache_create_write (doubly_sector);
      cache_close_write (doubly_sector);
    }
    // doubly -> indirect block
    disk_doubly = (struct doubly_disk *) cache_open_write (doubly_sector);
    block_sector_t indirect_sector = disk_doubly->indirect[idx.indirect];
    cache_close_write (doubly_sector);
    if (indirect_sector == 0)
    {
      // no indirect_sector, create indirect sector
      if (!free_map_allocate (1, &indirect_sector))
      {
        goto fail;
      }
      disk_doubly = (struct doubly_disk *) cache_open_write (doubly_sector);
      disk_doubly->indirect[idx.indirect] = indirect_sector;
      cache_close_write (doubly_sector);
      // zero indirect_sector
      cache_create_write (indirect_sector);
      cache_close_write (indirect_sector);
    }
    // doubly -> indirect -> direct block
    disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
    block_sector_t direct_sector = disk_indirect->direct[idx.direct];
    cache_close_write (indirect_sector);
    if (direct_sector == 0)
    {
      // no direct_sector, create direct sector
      if (!free_map_allocate (1, &direct_sector))
      {
        goto fail;
      }
      disk_indirect = (struct indirect_disk *) cache_open_write (indirect_sector);
      disk_indirect->direct[idx.direct] = direct_sector;
      cache_close_write (indirect_sector);
      // zero direct_sector
      cache_create_write (direct_sector);
      cache_close_write (direct_sector);
    }
  }
  return true;
fail:
  return false;
}
