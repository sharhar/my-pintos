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

#define SYSCALL_ENTRY(NUM, FUNC, ARGNUM) case NUM: check_user_pointer((char*)args, (ARGNUM + 1) * 4); FUNC(args, &f->eax); break;

static struct lock global_file_lock;
static int current_file_count = 3;

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

static void check_user_string(char* user_str) {
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
  check_user_string(filename);
  *f_eax = process_execute(filename);
}

static void syscall_wait(uint32_t* args, uint32_t* f_eax) {
  *f_eax = process_wait(args[1]);
}

static void syscall_compute_e(uint32_t* args, uint32_t* f_eax) {
  *f_eax = sys_sum_to_e(args[1]);
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
  }

  thread_current()->in_syscall = false;
}

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }
