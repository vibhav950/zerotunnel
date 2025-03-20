#pragma once

#ifndef DEBUG
#error "Tests cannot be run without DEBUG; enable -DDEBUG while building tests"
#endif

#include "common/defines.h"

#include <stdlib.h>
#include <string.h>

#define ASSERT_EQ(a, b) ASSERT((a) == (b))

#define ASSERT_MEMEQ(a, b, len) ASSERT(!memcmp(a, b, len))

#define ASSERT_STREQ(a, b) ASSERT(!strcmp(a, b))

void read_hex(const char *hex, unsigned char *buf, int len);

#undef DEBUG
