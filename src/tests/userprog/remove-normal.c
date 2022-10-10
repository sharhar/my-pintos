/* Creates an ordinary empty file. */

#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
    CHECK(create("quux.dat", 0), "create quux.dat");
    CHECK(remove("quux.dat"), "remove quux.dat");

    CHECK(!remove("quux.dat"), "remove quux.dat again");
}
