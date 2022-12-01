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

#define BUFFER_CACHE_SIZE 64
#define BUFFER_CACHE_PAGE_COUNT DIV_ROUND_UP(BUFFER_CACHE_SIZE * BLOCK_SECTOR_SIZE, PGSIZE)

#define NO_SECTOR ((block_sector_t)-1)

#define DIRTY_BIT  ((uint8_t)1)
#define MAPPED_BIT ((uint8_t)2)

struct buffer_cache_entry {
  block_sector_t sector;
  uint64_t last_used;
  uint8_t flags;
  struct condition cond;
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

static uint32_t next_block_device_id;
static uint64_t usage_counter;
static struct lock buffer_cache_lock;
static uint8_t* buffer_cache_data;
static struct buffer_cache_entry buffer_cache[BUFFER_CACHE_SIZE];

void block_init(void) {
  next_block_device_id = 1;
  usage_counter = 1;
  lock_init(&buffer_cache_lock);
  buffer_cache_data = palloc_get_multiple(0, BUFFER_CACHE_PAGE_COUNT);

  for(int i = 0; i < BUFFER_CACHE_SIZE; i++) {
    cond_init(&buffer_cache[i].cond);
    buffer_cache[i].sector = NO_SECTOR;
    buffer_cache[i].last_used = 0;
    buffer_cache[i].flags = 0;
    buffer_cache[i].data = &buffer_cache_data[BLOCK_SECTOR_SIZE*i];
  }
}

void block_done(void) {
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

static struct buffer_cache_entry* find_entry(struct block* block, block_sector_t sector, bool* must_evict) {
  ASSERT(lock_held_by_current_thread(&buffer_cache_lock));

  uint64_t least_time = ((uint64_t)-1);
  struct buffer_cache_entry* lru_entry = NULL;

  *must_evict = false;

  for(int i = 0; i < BUFFER_CACHE_SIZE; i++) {
    if(buffer_cache[i].sector == sector)
      return &buffer_cache[i];

    if(buffer_cache[i].last_used < least_time && !(buffer_cache[i].flags & MAPPED_BIT)) {
      least_time = buffer_cache[i].last_used;
      lru_entry = &buffer_cache[i];
    }
  }

  *must_evict = true;

  return lru_entry;
}

void* block_map_sector(struct block* block, block_sector_t sector, bool coherent) {
  if(block->type != BLOCK_RAW)
    return block_map_sector(block->provider, sector + ((uint64_t)block->aux), coherent);

  lock_acquire(&buffer_cache_lock);

  bool must_evict;
  block_sector_t prev_sector = NO_SECTOR;
  bool write_back = false;
  struct buffer_cache_entry* entry = find_entry(block, sector, &must_evict);

  if(must_evict) {
    if(entry->flags & MAPPED_BIT)
      PANIC("Trying to evict mapped buffer cache entry!");

    if(entry->flags & DIRTY_BIT) write_back = true;
    prev_sector = entry->sector;
    entry->sector = sector;
    entry->flags = 0;
  }

  while(entry->flags & MAPPED_BIT)
    cond_wait(&entry->cond, &buffer_cache_lock);

  entry->flags = entry->flags | MAPPED_BIT;

  lock_release(&buffer_cache_lock);

  struct block_operations* ops = block->provider;

  if(write_back) {
    check_sector(block, sector);
    ASSERT(block->type != BLOCK_FOREIGN);
    ops->write(block->aux, prev_sector, entry->data);
    block->write_cnt++;
  }

  if(coherent && must_evict) {
    check_sector(block, sector);
    ops->read(block->aux, sector, entry->data);
    block->read_cnt++;
  }

  return entry->data;
}

void block_unmap_sector(struct block* block, block_sector_t sector, bool dirty) {
  if(block->type != BLOCK_RAW) {
    block_unmap_sector(block->provider, sector + ((uint64_t)block->aux), dirty);
    return;
  }

  lock_acquire(&buffer_cache_lock);

  bool must_evict;
  struct buffer_cache_entry* entry = find_entry(block, sector, &must_evict);

  if(must_evict || entry == NULL)
    PANIC("Trying to unmap block sector that is not mapped!");

  entry->flags = entry->flags & (~MAPPED_BIT);
  entry->last_used = usage_counter++;

  if(dirty)
    entry->flags = entry->flags | DIRTY_BIT;

  cond_signal(&entry->cond, &buffer_cache_lock);
  
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
  block->id = next_block_device_id++;
  
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
