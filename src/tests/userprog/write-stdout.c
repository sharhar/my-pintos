/* Try writing a file in the most normal way. */

#include <syscall.h>
#include "tests/userprog/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int byte_cnt;

  byte_cnt = write(1, sample, sizeof sample - 1);
  if (byte_cnt != sizeof sample - 1)
    fail("write() returned %d instead of %zu", byte_cnt, sizeof sample - 1);
}
