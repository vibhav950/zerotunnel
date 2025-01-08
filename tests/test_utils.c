#include "test.h"

#include <stdio.h>

void read_hex(const char *hex, unsigned char *buf, const int len) {
   int i;
   unsigned int value;

  for (i = 0; i < len; ++i) {
    sscanf(hex + 2 * i, "%02x", &value);
    buf[i] = (uint8_t)value;
  }
}
