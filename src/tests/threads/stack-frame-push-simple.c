#include <stdio.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"
#include "threads/interrupt.h"

static void new_function_to_exec_first() {
    msg("Your stack has been hacked!");
}

static void new_function_to_exec_second() {
    msg("And now you've fallen for my SECOND trap card!");
}

static void my_helper_func(struct semaphore* semas) {
    msg("Helper thread start");

    sema_up(&semas[0]);
    sema_down(&semas[1]);

    msg("Helper thread end");

    sema_up(&semas[0]);
}

void stack_frame_push_test(void) {
    struct semaphore semas[2];
    sema_init(&semas[0], 0); 
    sema_init(&semas[1], 0);

    struct thread* t1 = thread_create("", PRI_DEFAULT, my_helper_func, semas);
    if(t1 == NULL)
        fail("Could not create thread!\n");

    msg("Created thread");
    sema_down(&semas[0]);

    enum intr_level old_level = intr_disable();
    thread_stack_frame_push(t1, new_function_to_exec_second);
    thread_stack_frame_push(t1, new_function_to_exec_first);
    intr_set_level(old_level);

    sema_up(&semas[1]);

    sema_down(&semas[0]);
    msg("Joined thread");

    pass();
}
