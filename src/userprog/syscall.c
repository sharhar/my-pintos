#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include <lib/kernel/console.h>
#include <threads/vaddr.h>

#define SYSCALL_ENTRY(NUM, FUNC, ARGNUM) case NUM: check_user_pointer(args, ARGNUM * 4 + 3); FUNC(args, &f->eax); break;

static void syscall_handler(struct intr_frame*);

static void check_user_pointer(char* userPtr, size_t memSize) {
  if(!is_user_vaddr(userPtr) || !is_user_vaddr(userPtr + memSize)) {
    char* proc_name = thread_current()->pcb->process_name;
    printf("%s: exit(%d)\n", proc_name, -1);
    process_exit();
    NOT_REACHED();
  }
}

static void syscall_exit(uint32_t* args, uint32_t* f_eax) {
  *f_eax = args[1];
  char* proc_name = thread_current()->pcb->process_name;
  printf("%s: exit(%d)\n", proc_name, args[1]);
  process_exit();
  NOT_REACHED();
}

static void syscall_write(uint32_t* args, uint32_t* f_eax) {
  if(args[1] == 1) {
    putbuf((void*)args[2], args[3]);
  }
}

static void syscall_practice(uint32_t* args, uint32_t* f_eax) {
  *f_eax = args[1] + 1;
}

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  struct process* proc = thread_current()->pcb;

  proc->in_syscall = true;

  uint32_t* args = ((uint32_t*)f->esp);

  switch (args[0]) {
    SYSCALL_ENTRY(SYS_EXIT, syscall_exit, 1)
    SYSCALL_ENTRY(SYS_WRITE, syscall_write, 3)
    SYSCALL_ENTRY(SYS_PRACTICE, syscall_practice, 1)
  }

  proc->in_syscall = false;
}
