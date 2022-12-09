#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include <threads/malloc.h>

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);
static void set_dir_parent(block_sector_t sector, block_sector_t parent);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();

  set_dir_parent(ROOT_DIR_SECTOR, ROOT_DIR_SECTOR);
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  int copy_amount = 0;
  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX && copy_amount < NAME_MAX) {
      copy_amount++;
      *dst++ = *src;
    } else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return copy_amount;
}

static struct inode* get_inode_from_path(const char* name, struct dir** parent_dir, char* file_name, bool* is_dir) {
  char* my_name = name;

  struct inode* result = inode_open(ROOT_DIR_SECTOR);
  struct dir* curr_dir = NULL;

  char part[NAME_MAX + 1];
  while(true) {
    int part_len = get_next_part(part, &my_name);
    if(part_len == 0) {
      *parent_dir = curr_dir;
      return result;
    } else if(part_len == -1) {
      dir_close(curr_dir);
      *parent_dir = NULL;
      return NULL;
    }

    dir_close(curr_dir);

    curr_dir = dir_open(result);
    if(curr_dir == NULL) {
      *parent_dir = NULL;
      return NULL;
    }

    memcpy(file_name, part, NAME_MAX + 1);

    dir_lookup(curr_dir, part, &result, is_dir);
  }

  return NULL;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size, bool is_dir) {
  struct dir* dir;
  char file_name[NAME_MAX + 1];
  struct inode* search_result = get_inode_from_path(name, &dir, file_name, NULL);

  if(search_result != NULL || dir == NULL) {
    inode_close(search_result);
    dir_close(dir);
    return false;
  }

  block_sector_t inode_sector = 0;
  if(!free_map_allocate(1, &inode_sector)) {
    dir_close(dir);
    return false;
  }

  if(!inode_create(inode_sector, initial_size)) {
    free_map_release(inode_sector, 1);
    dir_close(dir);
    return false;
  }

  if(!dir_add(dir, file_name, inode_sector, is_dir)) {
    struct inode* inode = inode_open(inode_sector);
    inode_remove(inode);
    inode_close(inode);
    free_map_release(inode_sector, 1);
    dir_close(dir);
    return false;
  }

  if(is_dir)
    set_dir_parent(inode_sector, inode_get_inumber(dir_get_inode(dir)));

  dir_close(dir);

  return true;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode* filesys_open(const char* name, bool* is_dir) {
  struct dir* dir;
  char file_name[NAME_MAX + 1];
  *is_dir = false;
  struct inode* search_result = get_inode_from_path(name, &dir, file_name, is_dir);
  dir_close(dir);

  return search_result;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir;
  char file_name[NAME_MAX + 1];
  bool is_dir;
  struct inode* search_result = get_inode_from_path(name, &dir, file_name, &is_dir);\
  
  if(search_result == NULL || dir == NULL) {
    inode_close(search_result);
    dir_close(dir);
    return false;
  }

  if(is_dir) {
    struct dir* my_dir = dir_open(search_result);
    char temp[NAME_MAX + 1];
    
    if(dir_readdir(my_dir, temp)) {
      dir_close(my_dir);
      return false;
    }

    dir_close(my_dir);
  }

  inode_close(search_result);

  bool success = dir_remove(dir, file_name);

  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

static void set_dir_parent(block_sector_t sector, block_sector_t parent) {
  struct inode* inode = inode_open(sector);
  inode_write_at(inode, &parent, sizeof(block_sector_t), 0);
  inode_close(inode);
}