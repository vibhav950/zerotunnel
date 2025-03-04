#pragma once

#include "common/defines.h"

#include <stdlib.h>
#include <string.h>

#define ASSERT(expr)                                                           \
  do {                                                                         \
    if (!(expr)) {                                                             \
      PRINTERROR("Assertion failed");                                          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_EQ(a, b)                                                        \
  do {                                                                         \
    if ((a) != (b)) {                                                          \
      PRINTERROR("Assertion failed");                                          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_STREQ(a, b)                                                     \
  do {                                                                         \
    if (strcmp((a), (b))) {                                                    \
      PRINTERROR("Assertion failed");                                          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_MEMEQ(a, b, len)                                                \
  do {                                                                         \
    if (memcmp((a), (b), (len))) {                                             \
      PRINTERROR("Assertion failed");                                          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

void read_hex(const char *hex, unsigned char *buf, int len);
