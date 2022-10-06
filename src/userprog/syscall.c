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

#define SYSCALL_ENTRY(NUM, FUNC, ARGNUM) case NUM: check_user_pointer((char*)args, (ARGNUM + 1) * 4); FUNC(args, &f->eax); break;

static void syscall_handler(struct intr_frame*);

static void check_user_pointer(char* userPtr, size_t memSize) {
  /* We have a clause in exception.c to handle invalid pointer dereferencing of a
      userspace pointer while in kernel mode. Therefore, the only validation we need 
      to do in syscall.c with user pointers is to make sure that they are below PHYS_BASE 
      (which we can check for using the `is_user_vaddr` function). Furthermore, we only 
      need to check the last byte of the provided user buffer since the only thing we need 
      to know is whether or not the buffer is fully within userspace, and the begining of 
      the buffer will always be below the end of it, we only need to check the end to ensure
      that the whole block of memory is within userspace. */

  if(!is_user_vaddr(userPtr + memSize - 1)) { 
    char* proc_name = thread_current()->pcb->process_name;
    printf("%s: exit(%d)\n", proc_name, -1);
    process_exit();
    NOT_REACHED();
  }
}

static void syscall_exit(uint32_t* args, uint32_t* f_eax) {
  struct process* curr_pcb = thread_current()->pcb;
  *f_eax = args[1];
  if(curr_pcb->parental_control_block != NULL) curr_pcb->parental_control_block->exit_code = args[1];
  printf("%s: exit(%d)\n", curr_pcb->process_name, args[1]);
  process_exit();
  NOT_REACHED();
}

static void syscall_write(uint32_t* args, UNUSED uint32_t* f_eax) {
  if(args[1] == 1) {
    putbuf((void*)args[2], args[3]);
  }
}

static void syscall_practice(uint32_t* args, uint32_t* f_eax) {
  *f_eax = args[1] + 1;
}

static void syscall_halt(uint32_t* args, uint32_t* f_eax) {
  shutdown_power_off();
  NOT_REACHED();
}

static void syscall_exec(uint32_t* args, uint32_t* f_eax) {
  char* filename = (char*)args[1];
  size_t filenameLen = strnlen(filename, PGSIZE);

  check_user_pointer(filename, filenameLen);

  *f_eax = process_execute(filename);
}

static void syscall_wait(uint32_t* args, uint32_t* f_eax) {
  *f_eax = process_wait(args[1]);
}

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  check_user_pointer((char*)args, 4);

  switch (args[0]) {
    SYSCALL_ENTRY(SYS_EXIT, syscall_exit, 1)
    SYSCALL_ENTRY(SYS_WRITE, syscall_write, 3)
    SYSCALL_ENTRY(SYS_PRACTICE, syscall_practice, 1)
    SYSCALL_ENTRY(SYS_HALT, syscall_halt, 0)
    SYSCALL_ENTRY(SYS_EXEC, syscall_exec, 1)
    SYSCALL_ENTRY(SYS_WAIT, syscall_wait, 1)
  }
}
