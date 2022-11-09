#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/syscall.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp, struct file** filePtr);
bool setup_thread(void (**eip)(void), void** esp);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  lock_init(&t->pcb->children_lock);
  list_init(&t->pcb->children);
  list_init(&t->pcb->files);

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

struct process_start_info {
  struct child_process* newProc;
  struct semaphore* sema;
  bool* exec_success;
  char* filename;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  struct process_start_info* fn_copy;

  struct child_process* newProc = malloc(sizeof(struct child_process));
  struct semaphore sema;
  bool exec_success = false;

  sema_init(&sema, 0);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return -1;
  
  fn_copy->newProc = newProc;
  fn_copy->sema = &sema;
  fn_copy->exec_success = &exec_success;
  fn_copy->filename = ((char*)fn_copy) + sizeof(struct process_start_info);
  
  strlcpy(fn_copy->filename, file_name, PGSIZE - sizeof(struct process_start_info));

  /* since the file_name variable contains both the filename
     and the arguments, we have to parse out just the filename
     before we give it to the thread_create. Otherwise, our threads
     have the wrong name and it messes with the autograder. */
  size_t filenameLen = strlen(file_name);
  size_t real_file_name_len = 0;

  for(; real_file_name_len < filenameLen; real_file_name_len++) {
    if(file_name[real_file_name_len] == ' ') break; 
  }

  char real_file_name[real_file_name_len+1];
  strlcpy(real_file_name, file_name, real_file_name_len+1);

  /* Create a new thread to execute FILE_NAME. */
  if (thread_create(real_file_name, PRI_DEFAULT, start_process, fn_copy) == NULL)
    palloc_free_page(fn_copy);
  
  sema_down(&sema);

  if(!exec_success) {
    free(newProc);
    return -1;
  }

  struct process* pcb = thread_current()->pcb;
  lock_acquire(&pcb->children_lock);
  list_push_back(&pcb->children, &newProc->elem);
  lock_release(&pcb->children_lock);

  return newProc->pid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* _startInfo) {
  struct process_start_info* startInfo = (struct process_start_info*) _startInfo;
  char* file_name = (char*) startInfo->filename;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;
  struct file* proc_file_handle;

  /* Allocate process control block */
  struct process* new_pcb = palloc_get_page(0);
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    t->pcb->parental_control_block = startInfo->newProc;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);


    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(file_name, &if_.eip, &if_.esp, &proc_file_handle);
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    palloc_free_page(pcb_to_free);
  }

  struct semaphore* start_sema = startInfo->sema;
  bool* exec_success = startInfo->exec_success;

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(_startInfo);
  if (!success) {
    sema_up(start_sema);
    thread_exit();
  }

  /* In this section we initialize all the variables in struct process */
  t->pcb->parental_control_block->reference_count = 2;
  t->pcb->parental_control_block->exit_code = -1;
  t->pcb->parental_control_block->pid = thread_tid();
  
  lock_init(&t->pcb->parental_control_block->reference_lock);
  sema_init(&t->pcb->parental_control_block->sem, 0);

  list_init(&t->pcb->heap_pages);
  lock_init(&t->pcb->heap_lock);

  lock_init(&t->pcb->threads_lock);
  lock_init(&t->pcb->locks_lock);
  lock_init(&t->pcb->semaphores_lock);
  lock_init(&t->pcb->children_lock);

  t->pcb->next_lock_ID = 0;
  t->pcb->next_sema_ID = 0;

  list_init(&t->pcb->children);
  list_init(&t->pcb->files);
  list_init(&t->pcb->user_threads);
  list_init(&t->pcb->user_locks);
  list_init(&t->pcb->user_semaphores);


  /* In this section we finish intilizing the lists in 
     struct process by adding all the initial elements
     needed for a process.*/
    
  // Init the alloc-only process heap
  struct process_heap_page* heap_page = t->pcb + 1;
  heap_page->freeBase = heap_page + 1;
  heap_page->freeSpace = PGSIZE - sizeof(struct process_heap_page) 
                                - sizeof(struct process);
  list_push_front(&t->pcb->heap_pages, &heap_page->elem);

  struct process_file* proc_file = process_heap_alloc(sizeof(struct process_file));
  proc_file->fd = 2;
  proc_file->filePtr = proc_file_handle;
  list_push_front(&t->pcb->files, &proc_file->elem);

  struct user_thread* uthread = process_heap_alloc(sizeof(struct user_thread));
  uthread->tid = thread_tid();
  uthread->exiting = false;
  uthread->user_stack = pg_round_down(if_.esp);
  lock_init(&uthread->lock);
  thread_current()->user_control = uthread;
  lock_acquire(&uthread->lock);

  *exec_success = true;

  sema_up(start_sema);

  asm volatile("fninit; fsave (%0)" : : "g"(&if_.fpuState));

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  struct process* pcb = thread_current()->pcb;

  lock_acquire(&pcb->children_lock);

  struct child_process* child_proc = NULL;
  struct list_elem* e = list_begin(&pcb->children);
  while(e != list_end(&pcb->children)) {
    struct child_process* cp = list_entry(e, struct child_process, elem);

    if(cp->pid == child_pid) {
      child_proc = cp;
      break;
    }

    e = list_next(e);
  }

  lock_release(&pcb->children_lock);

  int return_code = -1;

  if(child_proc != NULL) {
    sema_down(&child_proc->sem);
    list_remove(&child_proc->elem);
    return_code = child_proc->exit_code;
    free(child_proc);
  }

  return return_code;
}

static void free_process_children(struct process* pcb) {
  struct list_elem* e;

  int list_len = list_size(&pcb->children);

  void* to_be_deleted_pointers[list_len];
  int child_process_index = 0;

  for(e = list_begin(&pcb->children); e != list_end(&pcb->children); e = list_next(e)) {
    struct child_process* cp = list_entry(e, struct child_process, elem);

    bool to_be_deleted = false;

    lock_acquire(&cp->reference_lock);

    cp->reference_count--;

    if(cp->reference_count == 0) {
      to_be_deleted = true;
    }

    lock_release(&cp->reference_lock);

    if(to_be_deleted) {
      to_be_deleted_pointers[child_process_index] = cp;
    } else {
      to_be_deleted_pointers[child_process_index] = NULL;
    }

    child_process_index++;
  }

  ASSERT(child_process_index == list_len);

  for(int i = 0; i < list_len; i++) {
    if(to_be_deleted_pointers[i] != NULL) free(to_be_deleted_pointers[i]);
  }

  if(pcb->parental_control_block != NULL) {
    struct child_process* child_proc = pcb->parental_control_block;

    bool to_be_deleted = false;

    lock_acquire(&child_proc->reference_lock);

    child_proc->reference_count--;

    if(child_proc->reference_count == 0) {
      to_be_deleted = true;
    }

    lock_release(&child_proc->reference_lock);

    sema_up(&child_proc->sem);

    if(to_be_deleted) {
      free(child_proc);
    }
  }
}

static void close_process_files(struct process* pcb) {
  struct list_elem* e;

  if(!lock_held_by_current_thread(&global_file_lock))
    lock_acquire(&global_file_lock);

  for(e = list_begin(&pcb->files); e != list_end(&pcb->files); e = list_next(e)) {
    struct process_file* pf = list_entry(e, struct process_file, elem);

    file_close(pf->filePtr);
  }

  lock_release(&global_file_lock);
}

/* Free the current process's resources. */
void process_exit(int exit_code) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  // TODO: add pthread exit to call stack of all OTHER threads

  pthread_exit();

  struct process* pcb = cur->pcb;
  cur->pcb = NULL;
  
  //Join on all threads
  struct list_elem* e = list_begin(&pcb->user_threads);
  while(e != list_end(&pcb->user_threads)) {
    struct user_thread* uthread = list_entry(e, struct user_thread, elem);
    lock_acquire(&uthread->lock);
    lock_release(&uthread->lock);
    e = list_next(e);
  }

  if(pcb->parental_control_block != NULL)
    pcb->parental_control_block->exit_code = exit_code;
  
  printf("%s: exit(%d)\n", pcb->process_name, exit_code);

  free_process_children(pcb);
  close_process_files(pcb);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
  
  // Free all the pages of the process
  ASSERT(list_size(&pcb->heap_pages) > 0);
  ASSERT(pg_round_down(list_end(&pcb->heap_pages)->prev) == pcb);
  
  e = list_begin(&pcb->heap_pages);
  void* last_addr = list_end(&pcb->heap_pages);
  while(e != last_addr) {
    void* page_addr = pg_round_down(e);
    e = list_next(e);
    palloc_free_page(page_addr);
  }

  thread_exit();
}


/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* Allocates a buffer on the process's heap pages. This 
   function should only be used to allocate small structs
   that the process needs throughout its life which don't
   need to be freed until the process exits (like user locks
   and user semaphores). DO NOT use this function to allocate
   large buffers!!! This function CANNOT allocate buffers
   larger than PGSIZE - sizeof(struct process_heap_page).*/
void* process_heap_alloc(size_t size) {
  if(size > PGSIZE - sizeof(struct process_heap_page))
    return NULL;

  struct process* pcb = thread_current()->pcb;
  if(pcb == NULL) return NULL;
  
  lock_acquire(&pcb->heap_lock);

  // Search for space on existing pages and allocate if found
  struct list_elem* e = list_begin(&pcb->heap_pages);
  while(e != list_end(&pcb->heap_pages)) {
    struct process_heap_page* heap_page = list_entry(e, struct process_heap_page, elem);

    if(heap_page->freeSpace >= size) {
      void* return_ptr = heap_page->freeBase;
      heap_page->freeBase += size;
      heap_page->freeSpace -= size;
      lock_release(&pcb->heap_lock);
      return return_ptr;
    }

    e = list_next(e);
  }

  // Allocate new heap page if no space is found
  struct process_heap_page* new_page = palloc_get_page(0);

  if(new_page == NULL) {
    lock_release(&pcb->heap_lock);
    return NULL;
  }

  new_page->freeBase = new_page + 1;
  new_page->freeSpace = PGSIZE - sizeof(struct process_heap_page);
  list_push_front(&pcb->heap_pages, &new_page->elem);

  void* return_ptr = new_page->freeBase;
  new_page->freeBase += size;
  new_page->freeSpace -= size;
  lock_release(&pcb->heap_lock);
  return return_ptr;
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp, int argc, char** argv, size_t argvSize);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp, struct file** filePtr) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  
  /* In this section of code we calculate the maximum value of argc.
     This allows us to properly allocate memory on the stack later
     in which we will put the arguments and argv. */

  size_t filenameLen = strlen(file_name);
  size_t argc_max = 2;

  for(size_t i = 0; i < filenameLen; i++) {
    if(file_name[i] == ' ') argc_max++;
  }

  size_t argv_size = argc_max * 4 + strlen(file_name) + 1; // size of argv buffer
  char argvMem[argv_size]; // allocating space on stack for argv buffer
  char** argv = (char**) argvMem; // recast the stack pointer to char** for 
                                  // actually writting the pointers to the arguments

  char* argvBaseMemPtr = argvMem + argc_max * 4; // Pointer to memory location where next argument should go
  char* argvBaseStackPtr = ((char*)PHYS_BASE) - argv_size + argc_max * 4; // Pointer to memory location where 
                                                                          // arguments are located after they 
                                                                          // will be placed on the user's stack

  /* This section of code actually parses file_name and 
     sets up the argv buffer with all the argument data. */
  char* token;
  char* rest = (char*) file_name;
  int argc = 0;
  while ((token = strtok_r(rest, " ", &rest))) {
    size_t tokenSize = strlen(token)+1;
    strlcpy(argvBaseMemPtr, token, tokenSize);

    argv[argc] = argvBaseStackPtr;
    argvBaseStackPtr += tokenSize;
    argvBaseMemPtr += tokenSize;

    argc++;
  }

  argv[argc] = NULL;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  // pass argc and argv data to setup_stack where they 
  // will be copied over to the user's stack memory
  if (!setup_stack(esp, argc, argv, argv_size)) 
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  
  *filePtr = file;
  
  //file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp, int argc, char** argv, size_t argvSize) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success) {
      // We copy the argv buffer to the top of the user's stack
      char* new_esp = ((char*)PHYS_BASE) - argvSize; 
      memcpy(new_esp, (void*)argv, argvSize);

      // calculate padding to ensure stack is 16 byte aligned
      size_t padding = ((uint32_t)new_esp - 8) % 16; 

      new_esp -= padding;

      // place a pointer to the start of the argv buffer, this will be our char** argv
      new_esp -= 4;
      *((char**)new_esp) = (new_esp + padding + 4);

      // place the argc value
      new_esp -= 4;
      *((int*)new_esp) = argc;

      //place dummy return address
      new_esp -= 4;
      *((void**)new_esp) = NULL;
      
      //set the user stack to point to our setup stack
      *esp = (void*)new_esp;
    } else {
      palloc_free_page(kpage);
    }
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { return -1; }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { return -1; }

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct user_thread* uthread = thread_current()->user_control;
  if(uthread == NULL) return;
  uthread->exiting = true;
  barrier();

  struct process* pcb = thread_current()->pcb;

  uint32_t stack_kpage = pagedir_get_page(pcb->pagedir, uthread->user_stack);
  ASSERT(stack_kpage != NULL)
  pagedir_clear_page(pcb->pagedir, uthread->user_stack);
  palloc_free_page(stack_kpage);

  lock_acquire(&pcb->locks_lock);

  struct list_elem* e = list_begin(&pcb->user_locks);
  while(e != list_end(&pcb->user_locks)) {
    struct user_lock* ulock = list_entry(e, struct user_lock, elem);
    if(lock_held_by_current_thread(&ulock->lock))
      lock_release(&ulock->lock);
    e = list_next(e);
  }

  lock_release(&pcb->locks_lock);

  lock_release(&uthread->lock);
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}
