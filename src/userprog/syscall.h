#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

extern struct lock global_file_lock;

void syscall_init(void);

#endif /* userprog/syscall.h */
