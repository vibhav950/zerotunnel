#ifndef __CBUF_H__
#define __CBUF_H__

#include "defines.h"

#include <stdatomic.h>

/**
 * @struct cbuf_t
 * @brief Lock-free single-producer single-consumer (SPSC) circular buffer.
 *
 * This structure represents a circular (ring) buffer designed for concurrent
 * read and write access by one reader and one writer thread.
 *
 * - Thread-safe for concurrent use by one reader and one writer thread,
 * NOT SAFE if multiple threads attempt to read or write simultaneously. All
 * synchronization is handled internally using atomic memory operations.
 *
 * - `readp` and `writep` are atomic pointers that "chase" each other. Readable
 * data is available between `readp` and `writep`. The buffer is considered full
 * when advancing the write pointer would cause it to equal the read pointer
 * (one byte is always left unused). The buffer is considered empty when `readp
 * == writep`.
 */
typedef struct cbuf_st {
  uint8_t *buf;
  _Atomic(uint8_t *) readp;
  _Atomic(uint8_t *) writep;
  size_t capacity;
} cbuf_t;

int cbuf_init(cbuf_t *cbuf, size_t capacity);

void cbuf_free(cbuf_t *cbuf);

ssize_t cbuf_write_blocking(cbuf_t *cbuf, const uint8_t *buf, size_t nbytes,
                            timediff_t timeout_msec);

ssize_t cbuf_read_blocking(cbuf_t *cbuf, uint8_t *buf, size_t nbytes,
                           timediff_t timeout_msec, bool all);

ssize_t cbuf_peek(cbuf_t *cbuf, uint8_t *buf, size_t nbytes);

#endif /* __CBUF_H__ */
