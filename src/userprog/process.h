#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include <devices/block.h>

typedef char lock_t;
typedef char sema_t;

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct child_process {
  pid_t pid;
  int exit_code;
  int reference_count;
  struct lock reference_lock;
  struct semaphore sem;
  struct list_elem elem;
};

struct process_file {
  int fd;
  void* handle;
  bool is_dir;
  struct list_elem elem;
};

struct user_thread {
  tid_t tid;
  struct thread* t;
  void* user_stack;
  struct lock lock;
  bool joined;
  struct list_elem elem;
};

struct user_lock {
  lock_t id;
  struct lock lock;
  struct list_elem elem;
};

struct user_semaphore {
  sema_t id;
  struct semaphore sema;
  struct list_elem elem;
};

struct process_heap_page {
  uint8_t* freeBase;
  size_t freeSpace;
  struct list_elem elem;
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  block_sector_t cwd_sector;
  struct dir* cwd;
  struct lock cwd_lock;

  struct child_process* parental_control_block;
  struct list children;

  struct list heap_pages;
  struct lock heap_lock;

  struct list files;
  struct lock files_lock;

  struct lock children_lock;

  struct list user_threads;
  struct list user_locks;
  struct list user_semaphores;

  lock_t next_lock_ID;
  sema_t next_sema_ID;

  struct lock threads_lock;
  struct lock locks_lock;
  struct lock semaphores_lock;

};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(int exit_code);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

void* process_heap_alloc(size_t size);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
void pthread_join_all();
void pthread_exit(void);

#endif /* userprog/process.h */
