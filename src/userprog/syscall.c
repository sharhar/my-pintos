#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include <lib/kernel/console.h>
#include <threads/vaddr.h>
#include <devices/shutdown.h>
#include <lib/string.h>
#include <lib/float.h>
#include <filesys/filesys.h>
#include <threads/malloc.h>
#include <filesys/file.h>
#include <devices/input.h>

#define SYSCALL_ENTRY(NUM, FUNC, ARGNUM) case NUM: check_user_pointer((char*)args, (ARGNUM + 1) * 4); FUNC(args, &f->eax); break;

#define SYSCALL_RETURN_FALSE_IF(_CONDITION) if(_CONDITION) { *f_eax = (uint32_t)false; return; }

struct lock global_file_lock;
static int next_fd = 3;

static void check_user_pointer(char* userPtr, size_t memSize) {
  /* We have a clause in exception.c to handle invalid pointer dereferencing of a
      userspace pointer while in kernel mode. Therefore, the only validation we need 
      to do in syscall.c with user pointers is to make sure that they are below PHYS_BASE 
      (which we can check for using the `is_user_vaddr` function). Furthermore, we only 
      need to check the last byte of the provided user buffer since the only thing we need 
      to know is whether or not the buffer is fully within userspace, and the begining of 
      the buffer will always be below the end of it, we only need to check the end to ensure
      that the whole block of memory is within userspace. */
  if(!is_user_vaddr(userPtr + memSize - 1)) process_exit(-1);
}

static void check_user_string(char* user_str) {
  if(user_str == NULL) process_exit(-1);

  /* We can just call strlen because if we ever reach an invalid page inside of strnlen 
     it will just trigger a page_fault which will be handled properly inside of exception.c.
     Therefore, if strnlen returns, then we know that all the characters inside the string 
     are in pages which are valid. So to finish the pointer validation, we make sure that the
     final byte in the string is actually inside of userspace memory before we return.*/
  size_t user_str_size = strlen(user_str); /* We don't use strnlen here because, if the user provides
                                              a string that is larger than the maxlen passed into strnlen,
                                              the strnlen function would simply return that maxlen, which
                                              when passed into the check_user_pointer function could return true
                                              even though the actuall null terminator is in an invalid page or
                                              in kernel space. */
  check_user_pointer(user_str, user_str_size+1 /* we add one to make sure we check that the NULL terminator is in userspace */);
}

static struct process_file* get_file_from_fd(struct list* files, int fd) {
  struct list_elem* e;

  for(e = list_begin(files); e != list_end(files); e = list_next(e)) {
    struct process_file* pf = list_entry(e, struct process_file, elem);

    if(pf->fd == fd) {
      return pf;
    }
  }

  return NULL;
}

static struct user_lock* get_lock_from_id(lock_t id) {
  struct process* pcb = thread_current()->pcb;

  lock_acquire(&pcb->locks_lock);

  struct list_elem* e = list_begin(&pcb->user_locks);
  while (e != list_end(&pcb->user_locks)) {
    struct user_lock* actual_lock = list_entry(e, struct user_lock, elem);
    if (actual_lock->id == id) {
      lock_release(&pcb->locks_lock);
      return actual_lock;
    }
    e = list_next(e);
  }

  lock_release(&pcb->locks_lock);

  return NULL;
}

static struct user_semaphore* get_sema_from_id(sema_t id) {
  struct process* pcb = thread_current()->pcb;

  lock_acquire(&pcb->semaphores_lock);

  struct list_elem* e = list_begin(&pcb->user_semaphores);
  while (e != list_end(&pcb->user_semaphores)) {
    struct user_semaphore* actual_semaphore = list_entry(e, struct user_semaphore, elem);
    if (actual_semaphore->id == id) {
      lock_release(&pcb->semaphores_lock);
      return actual_semaphore;
    }
    e = list_next(e);
  }

  lock_release(&pcb->semaphores_lock);

  return NULL;
}

static struct user_thread* get_thread_from_id(tid_t id) {
  struct process* pcb = thread_current()->pcb;

  lock_acquire(&pcb->threads_lock);

  struct list_elem* e = list_begin(&pcb->user_threads);
  while (e != list_end(&pcb->user_threads)) {
    struct user_thread* actual_thread = list_entry(e, struct user_thread, elem);
    if (actual_thread->tid == id) {
      lock_release(&pcb->threads_lock);
      return actual_thread;
    }
    e = list_next(e);
  }

  lock_release(&pcb->threads_lock);

  return NULL;
}

static void syscall_exit(int32_t* args, int32_t* f_eax) {
  *f_eax = args[1];
  process_exit(args[1]);
  NOT_REACHED();
}

static void syscall_practice(uint32_t* args, uint32_t* f_eax) {
  *f_eax = args[1] + 1;
}

static void syscall_halt(UNUSED uint32_t* args, UNUSED uint32_t* f_eax) {
  shutdown_power_off();
  NOT_REACHED();
}

static void syscall_exec(uint32_t* args, uint32_t* f_eax) {
  char* filename = (char*)args[1];
  check_user_string(filename);

  lock_acquire(&global_file_lock);
  *f_eax = process_execute(filename);
  lock_release(&global_file_lock);
}

static void syscall_wait(uint32_t* args, uint32_t* f_eax) {
  *f_eax = process_wait(args[1]);
}

static void syscall_compute_e(uint32_t* args, uint32_t* f_eax) {
  *f_eax = sys_sum_to_e(args[1]);
}

static void syscall_create(uint32_t* args, uint32_t* f_eax) {
  char* filename = (char*)args[1];
  check_user_string(filename);

  lock_acquire(&global_file_lock);
  *f_eax = filesys_create(filename, (off_t) args[2]);
  lock_release(&global_file_lock);
}

static void syscall_remove(uint32_t* args, uint32_t* f_eax) {
  char* filename = (char*)args[1];
  check_user_string(filename);

  lock_acquire(&global_file_lock);
  *f_eax = filesys_remove(filename);
  lock_release(&global_file_lock);
}

static void syscall_open(uint32_t* args, uint32_t* f_eax) {
  char* filename = (char*)args[1];
  check_user_string(filename);

  lock_acquire(&global_file_lock);

  struct file* my_file = filesys_open(filename);

  if(my_file == NULL) {
    *f_eax = (uint32_t) ((int)-1);
    lock_release(&global_file_lock);
    return;
  } 

  struct process_file* proc_file = process_heap_alloc(sizeof(struct process_file));
  proc_file->fd = next_fd;
  proc_file->filePtr = my_file;

  list_push_front(&thread_current()->pcb->files, &proc_file->elem);

  next_fd++;
  *f_eax = proc_file->fd;
  lock_release(&global_file_lock);
}

static void syscall_close(uint32_t* args, uint32_t* f_eax) {
  lock_acquire(&global_file_lock);

  struct process_file* proc_file = get_file_from_fd(&thread_current()->pcb->files, (int)args[1]);

  if(proc_file == NULL) {
    *f_eax = (uint32_t) ((int)-1);
    lock_release(&global_file_lock);
    return;
  }

  file_close(proc_file->filePtr);
  list_remove(&proc_file->elem);

  *f_eax = 0;
  lock_release(&global_file_lock);
}

static void syscall_filesize(uint32_t* args, uint32_t* f_eax) {
  lock_acquire(&global_file_lock);

  struct process_file* proc_file = get_file_from_fd(&thread_current()->pcb->files, (int)args[1]);

  if(proc_file == NULL) {
    *f_eax = (uint32_t) ((int)-1);
    lock_release(&global_file_lock);
    return;
  }

  *f_eax = file_length(proc_file->filePtr);
  lock_release(&global_file_lock);
}

static void syscall_tell(uint32_t* args, uint32_t* f_eax) {
  lock_acquire(&global_file_lock);

  struct process_file* proc_file = get_file_from_fd(&thread_current()->pcb->files, (int)args[1]);

  if(proc_file == NULL) {
    *f_eax = (uint32_t) ((int)-1);
    lock_release(&global_file_lock);
    return;
  }

  *f_eax = file_tell(proc_file->filePtr);
  lock_release(&global_file_lock);
}

static void syscall_seek(uint32_t* args, uint32_t* f_eax) {
  lock_acquire(&global_file_lock);

  struct process_file* proc_file = get_file_from_fd(&thread_current()->pcb->files, (int)args[1]);

  if(proc_file == NULL) {
    *f_eax = (uint32_t) ((int)-1);
    lock_release(&global_file_lock);
    return;
  }

  file_seek(proc_file->filePtr, (off_t)args[2]);
  *f_eax = 0;
  lock_release(&global_file_lock);
} 

static void syscall_read(uint32_t* args, uint32_t* f_eax) {
  int fd = (int)args[1];
  void* user_buffer = (void*)args[2];
  unsigned user_buffer_size = (unsigned)args[3];

  check_user_pointer(user_buffer, user_buffer_size);

  if(fd == 0) {
    uint8_t* userReadBuff = (uint8_t*)user_buffer;

    for(size_t i = 0; i < user_buffer_size; i++) {
      userReadBuff[i] = input_getc();
    }

    *f_eax = user_buffer_size;
  } else {
    lock_acquire(&global_file_lock);

    struct process_file* proc_file = get_file_from_fd(&thread_current()->pcb->files, fd);

    if(proc_file == NULL) {
      *f_eax = (uint32_t) ((int)-1);
      lock_release(&global_file_lock);
      return;
    }

    *f_eax = file_read(proc_file->filePtr, user_buffer, user_buffer_size);

    lock_release(&global_file_lock);
  }
}

static void syscall_write(uint32_t* args, UNUSED uint32_t* f_eax) {
  int fd = (int)args[1];
  void* user_buffer = (void*)args[2];
  unsigned user_buffer_size = (unsigned)args[3];

  check_user_pointer(user_buffer, user_buffer_size);

  if(args[1] == 1) {
    putbuf(user_buffer, user_buffer_size);
    *f_eax = user_buffer_size;
  } else {
    lock_acquire(&global_file_lock);

    struct process_file* proc_file = get_file_from_fd(&thread_current()->pcb->files, fd);

    if(proc_file == NULL) {
      *f_eax = (uint32_t) ((int)-1);
      lock_release(&global_file_lock);
      return;
    }

    *f_eax = file_write(proc_file->filePtr, user_buffer, user_buffer_size);

    lock_release(&global_file_lock);
  }
}

static void syscall_lock_init(uint32_t* args, uint32_t* f_eax) {
  lock_t* lock = (lock_t*)args[1];
  SYSCALL_RETURN_FALSE_IF(lock == NULL) 

  struct user_lock* actual_lock = process_heap_alloc(sizeof(struct user_lock));
  SYSCALL_RETURN_FALSE_IF(actual_lock == NULL) 
  lock_init(&actual_lock->lock);

  struct process* pcb = thread_current()->pcb;
  
  lock_acquire(&pcb->locks_lock);
  
  actual_lock->id = pcb->next_lock_ID++;
  list_push_back(&pcb->user_locks, &actual_lock->elem);

  lock_release(&pcb->locks_lock);

  *lock = actual_lock->id;
  *f_eax = (uint32_t)true;
}

static void syscall_lock_acquire(uint32_t* args, uint32_t* f_eax) {
  lock_t* lock = (lock_t*)args[1];
  SYSCALL_RETURN_FALSE_IF(lock == NULL) 

  struct user_lock* actual_lock = get_lock_from_id(*lock);
  SYSCALL_RETURN_FALSE_IF(actual_lock == NULL || lock_held_by_current_thread(&actual_lock->lock))

  lock_acquire(&actual_lock->lock);

  *f_eax = (uint32_t)true;
}

static void syscall_lock_release(uint32_t* args, uint32_t* f_eax) {
  lock_t* lock = (lock_t*)args[1];
  SYSCALL_RETURN_FALSE_IF(lock == NULL) 

  struct user_lock* actual_lock = get_lock_from_id(*lock);
  SYSCALL_RETURN_FALSE_IF(actual_lock == NULL || !lock_held_by_current_thread(&actual_lock->lock)) 

  lock_release(&actual_lock->lock);

  *f_eax = (uint32_t)true;
}

static void syscall_sema_init(uint32_t* args, uint32_t* f_eax) {
  sema_t* sema = (sema_t*)args[1];
  int value = (int)args[2];

  SYSCALL_RETURN_FALSE_IF(sema == NULL || value < 0) 

  struct user_semaphore* actual_sema = process_heap_alloc(sizeof(struct user_semaphore));
  SYSCALL_RETURN_FALSE_IF(actual_sema == NULL) 
  sema_init(&actual_sema->sema, value);

  struct process* pcb = thread_current()->pcb;
  
  lock_acquire(&pcb->semaphores_lock);

  actual_sema->id = pcb->next_sema_ID++;
  list_push_back(&pcb->user_semaphores, &actual_sema->elem);

  lock_release(&pcb->semaphores_lock);

  *sema = actual_sema->id;
  *f_eax = (uint32_t)true;
}

static void syscall_sema_down(uint32_t* args, uint32_t* f_eax) {
  sema_t* sema = (sema_t*)args[1];
  SYSCALL_RETURN_FALSE_IF(sema == NULL)

  struct user_semaphore* actual_sema = get_sema_from_id(*sema);
  SYSCALL_RETURN_FALSE_IF(actual_sema == NULL) 

  sema_down(&actual_sema->sema);
  *f_eax = (uint32_t)true;
}

static void syscall_sema_up(uint32_t* args, uint32_t* f_eax) {
  sema_t* sema = (sema_t*)args[1];
  SYSCALL_RETURN_FALSE_IF(sema == NULL)

  struct user_semaphore* actual_sema = get_sema_from_id(*sema);
  SYSCALL_RETURN_FALSE_IF(actual_sema == NULL) 

  sema_up(&actual_sema->sema);
  *f_eax = (uint32_t)true;
}

static void syscall_get_tid(uint32_t* args, uint32_t* f_eax) {
  *f_eax = (uint32_t)thread_tid();
}

static void syscall_pthread_create(uint32_t* args, uint32_t* f_eax) {
  stub_fun sfun = (stub_fun)args[1];
  pthread_fun tfun = (pthread_fun)args[2];
  const void* arg = (void*)args[3];
  *f_eax = (uint32_t)pthread_execute(sfun, tfun, arg);
}

static void syscall_pthread_join(uint32_t* args, uint32_t* f_eax) {
  tid_t tid = (tid_t)args[1];

  struct user_thread* uthread = get_thread_from_id(tid);

  if(uthread == NULL || uthread->t == thread_current() || uthread->joined) {
    *f_eax = (uint32_t) TID_ERROR;
    return;
  }

  lock_acquire(&uthread->lock);
  uthread->joined = true;
  lock_release(&uthread->lock);
  
  *f_eax = (uint32_t)uthread->tid;
}

static void syscall_pthread_exit(uint32_t* args, uint32_t* f_eax) {
  if (thread_current() == thread_current()->pcb->main_thread) {
    lock_release(&thread_current()->user_control->lock);
    pthread_join_all();
    process_exit(0);
    NOT_REACHED();
  }

  pthread_exit();
  NOT_REACHED();
}

static void syscall_handler(struct intr_frame* f) {
  thread_current()->in_syscall = true;

  uint32_t* args = ((uint32_t*)f->esp);

  check_user_pointer((char*)args, 4);

  switch (args[0]) {
    SYSCALL_ENTRY(SYS_EXIT, syscall_exit, 1)
    SYSCALL_ENTRY(SYS_WRITE, syscall_write, 3)
    SYSCALL_ENTRY(SYS_PRACTICE, syscall_practice, 1)
    SYSCALL_ENTRY(SYS_HALT, syscall_halt, 0)
    SYSCALL_ENTRY(SYS_EXEC, syscall_exec, 1)
    SYSCALL_ENTRY(SYS_WAIT, syscall_wait, 1)
    SYSCALL_ENTRY(SYS_COMPUTE_E, syscall_compute_e, 1)
    SYSCALL_ENTRY(SYS_CREATE, syscall_create, 2)
    SYSCALL_ENTRY(SYS_REMOVE, syscall_remove, 1)
    SYSCALL_ENTRY(SYS_OPEN, syscall_open, 1)
    SYSCALL_ENTRY(SYS_CLOSE, syscall_close, 1)
    SYSCALL_ENTRY(SYS_FILESIZE, syscall_filesize, 1)
    SYSCALL_ENTRY(SYS_TELL, syscall_tell, 1)
    SYSCALL_ENTRY(SYS_SEEK, syscall_seek, 2)
    SYSCALL_ENTRY(SYS_READ, syscall_read, 3)
    SYSCALL_ENTRY(SYS_LOCK_INIT, syscall_lock_init, 1)
    SYSCALL_ENTRY(SYS_LOCK_ACQUIRE, syscall_lock_acquire, 1)
    SYSCALL_ENTRY(SYS_LOCK_RELEASE, syscall_lock_release, 1)
    SYSCALL_ENTRY(SYS_SEMA_INIT, syscall_sema_init, 2)
    SYSCALL_ENTRY(SYS_SEMA_UP, syscall_sema_up, 1)
    SYSCALL_ENTRY(SYS_SEMA_DOWN, syscall_sema_down, 1)
    SYSCALL_ENTRY(SYS_GET_TID, syscall_get_tid, 0)
    SYSCALL_ENTRY(SYS_PT_CREATE, syscall_pthread_create, 3)
    SYSCALL_ENTRY(SYS_PT_JOIN, syscall_pthread_join, 1)
    SYSCALL_ENTRY(SYS_PT_EXIT, syscall_pthread_exit, 0)
  }

  thread_current()->in_syscall = false;
}

void syscall_init(void) {
  lock_init(&global_file_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}
