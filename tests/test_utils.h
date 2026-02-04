#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <stdlib.h>

#define TEST_ASSERT(cond, msg)                    \
    do {                                          \
        if (!(cond)) {                            \
            fprintf(stderr,                       \
                    "[FAIL] %s:%d: %s\n",         \
                    __FILE__, __LINE__, msg);     \
            exit(1);                              \
        }                                         \
    } while (0)

#define TEST_PASS(msg)                            \
    do {                                          \
        printf("[PASS] %s\n", msg);               \
    } while (0)

#endif
