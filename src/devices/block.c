#include "devices/block.h"
#include <list.h>
#include <string.h>
#include <round.h>
#include <stdio.h>
#include <threads/palloc.h>
#include <threads/vaddr.h>
#include <threads/synch.h>
#include <bitmap.h>
#include "devices/ide.h"
#include "threads/malloc.h"
#include <threads/thread.h>

#define BUFFER_CACHE_SIZE 64
#define BUFFER_CACHE_PAGE_COUNT DIV_ROUND_UP(BUFFER_CACHE_SIZE * BLOCK_SECTOR_SIZE, PGSIZE)

#define DIRTY_BIT  ((uint8_t)1)
#define MAPPED_BIT ((uint8_t)2)
#define USED_BIT   ((uint8_t)4)

/* An entry in the buffer cache*/
struct buffer_cache_entry {
  struct block* block; // Physical block device where the data is stored
  
  /* Virtual device that mapped the sector (this will be different than 
     the `block` device if we are using a block struct made by partition.c)*/
  struct block* holder;

  block_sector_t sector; // Sector where data is stored on physical device
  uint64_t last_used;    // when was the entry last used
  uint8_t flags;         // contains entry flags: dirty?, mapped?
  struct condition cond; // conditional variable used for 
  uint8_t* data;
};

/* A block device. */
struct block {
  struct list_elem list_elem; /* Element in all_blocks. */

  char name[16];        /* Block device name. */
  enum block_type type; /* Type of block device. */
  block_sector_t size;  /* Size in sectors. */
  uint32_t id;

  void* provider;
  void* aux;

  unsigned long long read_cnt;  /* Number of sectors read. */
  unsigned long long write_cnt; /* Number of sectors written. */
};

/* List of all block devices. */
static struct list all_blocks = LIST_INITIALIZER(all_blocks);

/* The block block assigned to each Pintos role. */
static struct block* block_by_role[BLOCK_ROLE_CNT];

static struct block* list_elem_to_block(struct list_elem*);
static void flush_entry(struct block* block, block_sector_t sector, struct block* holder, void* data);

static uint64_t usage_counter;              // counter for when blocks are accessed
static struct lock buffer_cache_lock;       // global lock around buffer cache
static struct condition buffer_cache_cond;  // conditional variable for cache entries being unmapped
static uint8_t* buffer_cache_data;
static struct buffer_cache_entry buffer_cache[BUFFER_CACHE_SIZE];

void block_init(void) {
  usage_counter = 1;
  lock_init(&buffer_cache_lock);
  cond_init(&buffer_cache_cond);
  buffer_cache_data = palloc_get_multiple(0, BUFFER_CACHE_PAGE_COUNT);

  for(int i = 0; i < BUFFER_CACHE_SIZE; i++) {
    cond_init(&buffer_cache[i].cond);
    buffer_cache[i].block = NULL;
    buffer_cache[i].holder = NULL;
    buffer_cache[i].sector = BLOCK_SECTOR_NONE;
    buffer_cache[i].last_used = 0;
    buffer_cache[i].flags = 0;
    buffer_cache[i].data = &buffer_cache_data[BLOCK_SECTOR_SIZE*i];
  }
}

void block_done(void) {
  // Flush dirty cache entries to disk before shutdown
  for(int i = 0; i < BUFFER_CACHE_SIZE; i++)
    if(buffer_cache[i].block != NULL && buffer_cache[i].flags & DIRTY_BIT)
      flush_entry(buffer_cache[i].block, buffer_cache[i].sector, 
                  buffer_cache[i].holder, buffer_cache[i].data);

  palloc_free_multiple(buffer_cache_data, BUFFER_CACHE_PAGE_COUNT);
}

/* Returns a human-readable name for the given block device
   TYPE. */
const char* block_type_name(enum block_type type) {
  static const char* block_type_names[BLOCK_CNT] = {
      "kernel", "filesys", "scratch", "swap", "raw", "foreign",
  };

  ASSERT(type < BLOCK_CNT);
  return block_type_names[type];
}

/* Returns the block device fulfilling the given ROLE, or a null
   pointer if no block device has been assigned that role. */
struct block* block_get_role(enum block_type role) {
  ASSERT(role < BLOCK_ROLE_CNT);
  return block_by_role[role];
}

/* Assigns BLOCK the given ROLE. */
void block_set_role(enum block_type role, struct block* block) {
  ASSERT(role < BLOCK_ROLE_CNT);
  block_by_role[role] = block;
}

/* Returns the first block device in kernel probe order, or a
   null pointer if no block devices are registered. */
struct block* block_first(void) {
  return list_elem_to_block(list_begin(&all_blocks));
}

/* Returns the block device following BLOCK in kernel probe
   order, or a null pointer if BLOCK is the last block device. */
struct block* block_next(struct block* block) {
  return list_elem_to_block(list_next(&block->list_elem));
}

/* Returns the block device with the given NAME, or a null
   pointer if no block device has that name. */
struct block* block_get_by_name(const char* name) {
  struct list_elem* e;

  for (e = list_begin(&all_blocks); e != list_end(&all_blocks); e = list_next(e)) {
    struct block* block = list_entry(e, struct block, list_elem);
    if (!strcmp(name, block->name))
      return block;
  }

  return NULL;
}

/* Verifies that SECTOR is a valid offset within BLOCK.
   Panics if not. */
static void check_sector(struct block* block, block_sector_t sector) {
  if (sector >= block->size) {
    /* We do not use ASSERT because we want to panic here
         regardless of whether NDEBUG is defined. */
    PANIC("Access past end of device %s (sector=%" PRDSNu ", "
          "size=%" PRDSNu ")\n",
          block_name(block), sector, block->size);
  }
}

/* Searches for an available cache entry, returns only once
   entry is ready to be used by the map function. Sets
   MUST_EVICT to true if the returned entry must be evicted
   before being used. Also sets both the used bit and mapped
   bit in the entry (after waiting on any other threads)
   using the entries first to ensure no concurrent access. */
static struct buffer_cache_entry* select_entry(struct block* block, block_sector_t sector, bool* must_evict) {
  uint64_t least_time = ((uint64_t)-1);
  struct buffer_cache_entry* lru_entry = NULL;

  while(lru_entry == NULL) {
    for(int i = 0; i < BUFFER_CACHE_SIZE; i++) {
      // If sector is already mapped, return the entry
      if(buffer_cache[i].block == block && buffer_cache[i].sector == sector) {
        buffer_cache[i].flags |= USED_BIT;

        // If entry is currently mapped, wait for it to be unmapped
        while(buffer_cache[i].flags & MAPPED_BIT)
          cond_wait(&buffer_cache[i].cond, &buffer_cache_lock);

        buffer_cache[i].flags |= MAPPED_BIT;
        
        return &buffer_cache[i];
      }

      // Keep track of least recently used entry that is not currently being used
      if(buffer_cache[i].last_used < least_time && !(buffer_cache[i].flags & USED_BIT)) {
        least_time = buffer_cache[i].last_used;
        lru_entry = &buffer_cache[i];
      }
    }

    /* If all entries are mapped, wait on the cache-wide conditional variable
       then simply scan the cache again. */
    if(lru_entry == NULL)
      cond_wait(&buffer_cache_cond, &buffer_cache_lock);
  }

  lru_entry->flags |= USED_BIT;
  lru_entry->flags |= MAPPED_BIT;

  // No matching blocks were found, so we must evict the lru_entry
  *must_evict = true;

  return lru_entry;
}

void block_read_direct(struct block* block, block_sector_t sector, void* data) {
  struct block* device = block;
  block_sector_t physical_sector = sector;

  if(block != BLOCK_RAW) {
    device = block->provider;
    physical_sector = sector + ((uint64_t)block->aux);
  }

  struct block_operations* ops = device->provider;

  ops->read(device->aux, physical_sector, data);
  device->read_cnt++;

  if(block != BLOCK_RAW)
    block->read_cnt++;
}

void block_write_direct(struct block* block, block_sector_t sector, const void* data) {
  struct block* device = block;
  block_sector_t physical_sector = sector;

  if(block != BLOCK_RAW) {
    device = block->provider;
    physical_sector = sector + ((uint64_t)block->aux);
  }

  struct block_operations* ops = device->provider;

  ops->write(device->aux, physical_sector, data);
  device->write_cnt++;

  if(block != BLOCK_RAW)
    block->write_cnt++;
}

static void flush_entry(struct block* block, block_sector_t sector, struct block* holder, void* data) {
  // Write data to device
  ASSERT(block->type == BLOCK_RAW);

  struct block_operations* ops = block->provider;
  ops->write(block->aux, sector, data);
  block->write_cnt++;

  if(holder->type != BLOCK_RAW)
    holder->write_cnt++;
}

void* block_map_sector(struct block* vblock, block_sector_t vsector, bool coherent) {
  ASSERT(thread_current()->mapped_entry == NULL);

  check_sector(vblock, vsector);

  lock_acquire(&buffer_cache_lock);

  struct block* block = vblock;
  block_sector_t sector = vsector;
  if(vblock->type != BLOCK_RAW) {
    block = vblock->provider;
    sector = vsector + ((uint64_t)vblock->aux);
  }
  
  bool must_evict = false;
  struct buffer_cache_entry* entry = select_entry(block, sector, &must_evict);
  
  // If must_evict is true, we need to clean this entry before using it
  bool write_back = false;
  block_sector_t prev_sector = BLOCK_SECTOR_NONE;
  struct block* prev_block = NULL;
  struct block* prev_holder = NULL;
  if(must_evict) {
    /* If the entry is dirty, record what sector it used to point to
        so that it can be used later to evict the data. We cannot do 
        the eviction here because we are still holding the global
        cache lock. */
    if(entry->flags & DIRTY_BIT) {
      write_back = true;
      prev_block = entry->block;
      prev_sector = entry->sector;
      prev_holder = entry->holder;
    }

    entry->block = block;
    entry->sector = sector;
    entry->flags &= (~DIRTY_BIT);
  }

  entry->holder = vblock;

  thread_current()->mapped_entry = entry;

  lock_release(&buffer_cache_lock);
  
  // If the entry has only data 
  if(write_back)
    flush_entry(prev_block, prev_sector, prev_holder, entry->data);

  if(coherent && must_evict) {
    // Read data from device
    struct block_operations* ops = block->provider;
    ops->read(block->aux, sector, entry->data);
    block->read_cnt++;

    if(vblock->type != BLOCK_RAW)
      vblock->read_cnt++;
  }

  return entry->data;
}

void block_unmap_sector(struct block* block, block_sector_t sector, bool dirty) {
  ASSERT(thread_current()->mapped_entry != NULL);

  if(block->type != BLOCK_RAW) {
    block_unmap_sector(block->provider, sector + ((uint64_t)block->aux), dirty);
    return;
  }

  lock_acquire(&buffer_cache_lock);

  // Search for entry to be unmapped
  struct buffer_cache_entry* entry = NULL;
  for(int i = 0; i < BUFFER_CACHE_SIZE; i++) {
    if(buffer_cache[i].block == block && buffer_cache[i].sector == sector && buffer_cache[i].flags & MAPPED_BIT) {
      entry = &buffer_cache[i];
      break;
    }
  }

  // If entry is NULL, then we tried to unmap an entry that isn't mapped
  ASSERT(entry != NULL);
  ASSERT(thread_current()->mapped_entry == entry);

  entry->flags &= (~MAPPED_BIT);
  entry->last_used = usage_counter++;

  if(dirty)
    entry->flags |= DIRTY_BIT;

  
  thread_current()->mapped_entry = NULL;

  /* Signal any waiters, making sure to first signal threads
     which are trying to access the already present cache entry,
     then signal threads that seek to evict the entry. */
  if(!list_empty(&entry->cond.waiters)) {
    cond_signal(&entry->cond, &buffer_cache_lock);
  } else {
    entry->flags &= (~USED_BIT);
    cond_signal(&buffer_cache_cond, &buffer_cache_lock);
  }

  lock_release(&buffer_cache_lock);
}

/* Reads sector SECTOR from BLOCK into BUFFER, which must
   have room for BLOCK_SECTOR_SIZE bytes.
   Internally synchronizes accesses to block devices, so external
   per-block device locking is unneeded. */
void block_read(struct block* block, block_sector_t sector, void* buffer) {
  void* mapped_sector = block_map_sector(block, sector, true);
  memcpy(buffer, mapped_sector, BLOCK_SECTOR_SIZE);
  block_unmap_sector(block, sector, false);
}

/* Write sector SECTOR to BLOCK from BUFFER, which must contain
   BLOCK_SECTOR_SIZE bytes.  Returns after the block device has
   acknowledged receiving the data.
   Internally synchronizes accesses to block devices, so external
   per-block device locking is unneeded. */
void block_write(struct block* block, block_sector_t sector, const void* buffer) {
  void* mapped_sector = block_map_sector(block, sector, false);
  memcpy(mapped_sector, buffer, BLOCK_SECTOR_SIZE);
  block_unmap_sector(block, sector, true);
}

/* Returns the number of sectors in BLOCK. */
block_sector_t block_size(struct block* block) { return block->size; }

/* Returns BLOCK's name (e.g. "hda"). */
const char* block_name(struct block* block) { return block->name; }

/* Returns BLOCK's type. */
enum block_type block_type(struct block* block) { return block->type; }

/* Prints statistics for each block device used for a Pintos role. */
void block_print_stats(void) {
  int i;

  for (i = 0; i < BLOCK_ROLE_CNT; i++) {
    struct block* block = block_by_role[i];
    if (block != NULL) {
      printf("%s (%s): %llu reads, %llu writes\n", block->name, block_type_name(block->type),
             block->read_cnt, block->write_cnt);
    }
  }
}

/* Registers a new block device with the given NAME.  If
   EXTRA_INFO is non-null, it is printed as part of a user
   message.  The block device's SIZE in sectors and its TYPE must
   be provided, as well as the it operation functions OPS, which
   will be passed AUX in each function call. */
struct block* block_register(const char* name, enum block_type type, const char* extra_info,
                             block_sector_t size, void* provider, void* aux) {
  struct block* block = malloc(sizeof *block);
  if (block == NULL)
    PANIC("Failed to allocate memory for block device descriptor");

  list_push_back(&all_blocks, &block->list_elem);
  strlcpy(block->name, name, sizeof block->name);
  block->type = type;
  block->size = size;
  block->provider = provider;
  block->aux = aux;
  block->read_cnt = 0;
  block->write_cnt = 0;
  
  printf("%s: %'" PRDSNu " sectors (", block->name, block->size);
  print_human_readable_size((uint64_t)block->size * BLOCK_SECTOR_SIZE);
  printf(")");
  if (extra_info != NULL)
    printf(", %s", extra_info);
  printf("\n");

  return block;
}

/* Returns the block device corresponding to LIST_ELEM, or a null
   pointer if LIST_ELEM is the list end of all_blocks. */
static struct block* list_elem_to_block(struct list_elem* list_elem) {
  return (list_elem != list_end(&all_blocks) ? list_entry(list_elem, struct block, list_elem)
                                             : NULL);
}
