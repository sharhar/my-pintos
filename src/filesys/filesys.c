#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

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
    if (dst < part + NAME_MAX) {
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

static void to_absoulte_path(char* result, const char* path) {
  int part_len = 0;
  int32_t result_off = 0;
  do {
    result[result_off] = '/';
    result_off++;
    part_len = get_next_part(&result[result_off], &path);
    
    if(part_len == 1 && result[result_off] == '.') {
      result_off--;
    } else if(part_len == 2 && result[result_off] == '.' && result[result_off+1] == '.') {
      result_off -= 2;

      for(;result_off >= 0 && result[result_off] != '/'; result_off--);
    } else {
      result_off += part_len;
    }
    
  } while(part_len > 0);

  result[result_off-1] = '\0';
}

static struct inode* get_inode_from_path(const char* name, struct dir** parent_dir) {
  char clean_path[strlen(name) + 1];
  to_absoulte_path(clean_path, name);
  
  struct inode* result = inode_open(ROOT_DIR_SECTOR);
  struct dir* curr_dir = NULL;

  char part[NAME_MAX + 1];
  while(true) {
    int part_len = get_next_part(part, &clean_path);
    if(part_len == 0) {
      *parent_dir = curr_dir;
      return result;
    } else if(part_len == -1) {
      *parent_dir = NULL;
      return NULL;
    }

    curr_dir = dir_open(result);
    if(curr_dir == NULL) {
      *parent_dir = NULL;
      return NULL;
    }

    dir_lookup(curr_dir, part, &result);
  }

  return NULL;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  /*
  struct dir* dir;
  struct inode* search_result = get_inode_from_path(name, &dir);

  if(search_result != NULL || dir == NULL)
    return false;

  block_sector_t inode_sector = 0;
  if(!free_map_allocate(1, &inode_sector))
    return false;

  if(!inode_create(inode_sector, initial_size)) {
    free_map_release(inode_sector, 1);
    return false;
  }

  dir_close(dir);

  return true;

  */

  block_sector_t inode_sector = 0;
  struct dir* dir = dir_open_root();
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  struct dir* dir = dir_open_root();
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
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
