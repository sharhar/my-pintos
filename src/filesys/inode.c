#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include <threads/synch.h>
#include <threads/thread.h>

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define LENGTH_BIT ((block_sector_t)(1 << 31))
#define PAGE_ENTRY_COUNT (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))

#define GET_SECTOR(SEC) (SEC & (~LENGTH_BIT))

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  bool extensible;
  struct rw_lock lock;
};

enum AccessMode {
  MODE_READ_ONLY,
  MODE_READ_AND_WRITE
};

static bool block_exists(block_sector_t blck) {
  return (blck | LENGTH_BIT) != BLOCK_SECTOR_NONE;
}

static block_sector_t* change_mode(struct rw_lock* lock, bool* reader, block_sector_t sector, bool dirty, bool remap, enum AccessMode mode) {
  block_unmap_sector(fs_device, sector, dirty);
  rw_lock_release(lock, *reader);
  *reader = mode == MODE_READ_ONLY;
  rw_lock_acquire(lock, *reader);

  void* result = NULL;
  if(remap)
    result = block_map_sector(fs_device, sector, true);

  return result;
}

/* Finds the entry for the sector information we want. */
static block_sector_t find_entry(struct rw_lock* lock, block_sector_t sector, off_t index, bool make_if_absent, uint32_t clear_data, bool* reader) {
  block_sector_t* sector_mem = block_map_sector(fs_device, sector, true);

  // If the page is already allocated, just return it's sector
  if(block_exists(sector_mem[index]) || !make_if_absent) {
    block_unmap_sector(fs_device, sector, false);
    return sector_mem[index];
  }

  // Change to write enabled mode
  sector_mem = change_mode(lock, reader, sector, false, true, MODE_READ_AND_WRITE);

  // Check for the page entry again, maybe another thread already added it
  if(block_exists(sector_mem[index])) {
    block_sector_t result = sector_mem[index];
    change_mode(lock, reader, sector, false, false, MODE_READ_ONLY);
    return result;
  }

  //Otherwise, we allocate a new page
  block_sector_t new_page_sector;
  if(!free_map_allocate(1, &new_page_sector)) {
    change_mode(lock, reader, sector, false, false, MODE_READ_ONLY);
    return BLOCK_SECTOR_NONE;
  }

  uint32_t* new_sector = malloc(sizeof(uint32_t) * PAGE_ENTRY_COUNT);
  for(int i = 0; i < PAGE_ENTRY_COUNT; i++) {
    new_sector[i] = clear_data;
  }
  block_write_direct(fs_device, new_page_sector, new_sector);
  free(new_sector);

  sector_mem[index] = (sector_mem[index] & LENGTH_BIT) | GET_SECTOR(new_page_sector);
  change_mode(lock, reader, sector, true, false, MODE_READ_ONLY);
  return new_page_sector;
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos, bool make_if_absent) {
  ASSERT(inode != NULL);

  off_t sector_num = pos / BLOCK_SECTOR_SIZE;
  
  off_t page_index = sector_num / PAGE_ENTRY_COUNT;
  off_t sector_index = sector_num % PAGE_ENTRY_COUNT;

  bool reader = true;
  rw_lock_acquire(&inode->lock, reader);

  block_sector_t page = find_entry(&inode->lock, GET_SECTOR(inode->sector), page_index, make_if_absent, BLOCK_SECTOR_NONE, &reader);
  if(!block_exists(page)) {
    rw_lock_release(&inode->lock, reader);
    return BLOCK_SECTOR_NONE;
  }

  block_sector_t sector = find_entry(&inode->lock, GET_SECTOR(page), sector_index, make_if_absent, 0, &reader);
  if(!block_exists(sector)) {
    rw_lock_release(&inode->lock, reader);
    return BLOCK_SECTOR_NONE;
  }

  rw_lock_release(&inode->lock, reader);

  return GET_SECTOR(sector);
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

static void page_list_set_length(block_sector_t* page_list, off_t length) {
  for(int i = 0; i < 32; i++)
    page_list[i] = (page_list[i] & (~LENGTH_BIT)) | (((length >> i) & 1) << 31);
}

static off_t page_list_get_length(block_sector_t* page_list) {
  off_t result = 0;

  for(int i = 31; i >= 0; i--) {
    result = result | ((page_list[i] & LENGTH_BIT) >> 31);

    result = result << 1;
  }
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  ASSERT(length >= 0);

  size_t sectors_left = bytes_to_sectors(length);
  size_t page_num = DIV_ROUND_UP(sectors_left, PAGE_ENTRY_COUNT);

  void* zero_buff = malloc(BLOCK_SECTOR_SIZE);
  memset(zero_buff, 0, BLOCK_SECTOR_SIZE);

  block_sector_t* page_list = malloc(BLOCK_SECTOR_SIZE);

  for(int i = 0; i < PAGE_ENTRY_COUNT; i++) {
    if(i < page_num) {
      free_map_allocate(1, &page_list[i]);

      block_sector_t* sector_list = block_map_sector(fs_device, page_list[i], false);

      for(int j = 0; j < PAGE_ENTRY_COUNT; j++) {
        if(sectors_left > 0) {
          free_map_allocate(1, &sector_list[j]);
          block_write_direct(fs_device, sector_list[j], zero_buff);
          sectors_left--;
        } else {
          sector_list[j] = BLOCK_SECTOR_NONE;
        }
      }

      block_unmap_sector(fs_device, page_list[i], true);

    } else {
      page_list[i] = BLOCK_SECTOR_NONE;
    }
  }

  page_list_set_length(page_list, length);

  block_write(fs_device, sector, page_list);

  free(page_list);
  free(zero_buff);

  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  rw_lock_init(&inode->lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      rw_lock_acquire(&inode->lock, false);

      block_sector_t* page_list = malloc(512);
      block_read(fs_device, inode->sector, page_list);

      for(int i = 0; i < PAGE_ENTRY_COUNT; i++) {
        if(!block_exists(page_list[i]))
          continue;
        
        block_sector_t curr_page = GET_SECTOR(page_list[i]);
        
        block_sector_t* sector_list = block_map_sector(fs_device, curr_page, true);

        for(int j = 0; j < PAGE_ENTRY_COUNT; j++)
          if(block_exists(sector_list[j]))
            free_map_release(GET_SECTOR(sector_list[j]), 1);

        block_unmap_sector(fs_device, curr_page, false);
        free_map_release(curr_page, 1);
      }

      free_map_release(inode->sector, 1);

      free(page_list);
      rw_lock_release(&inode->lock, false);
      
      //free_map_release(inode->sector, 1);
      //free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  off_t inode_len = inode_length(inode);

  //if(inode_len < size + offset)
  //  inode_len = size + offset;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset, false);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_len - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if(block_exists(sector_idx)) {
      uint8_t* mapped_sector = block_map_sector(fs_device, sector_idx, true);
      memcpy(buffer + bytes_read, mapped_sector + sector_ofs, chunk_size);
      block_unmap_sector(fs_device, sector_idx, false);
    } else {
      memset(buffer + bytes_read, 0, chunk_size);
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
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;
  
  off_t inode_len = inode_length(inode);

  if(inode_len < size + offset) {
    block_sector_t* page_list = block_map_sector(fs_device, inode->sector, true);
    page_list_set_length(page_list, size + offset);
    block_unmap_sector(fs_device, inode->sector, true);
    inode_len = size + offset;
  }

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset, true);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_len - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    uint8_t* mapped_sector = block_map_sector(fs_device, sector_idx, sector_ofs > 0 || chunk_size < sector_left);
    memcpy(mapped_sector + sector_ofs, buffer + bytes_written, chunk_size);
    block_unmap_sector(fs_device, sector_idx, true);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) {
  block_sector_t* page_list = block_map_sector(fs_device, inode->sector, true);

  off_t result = page_list_get_length(page_list);

  block_unmap_sector(fs_device, inode->sector, false);

  return result;
}
