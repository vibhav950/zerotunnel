#pragma once

#include "defines.h"

#include <limits.h>
#include <stdatomic.h>

/* Min capacity of a cbuf for `cbuf_init()` and `cbuf_make()` */
#define CBUF_MIN_CAPACITY 512U
/* Max capacity of a cbuf for `cbuf_init()` and `cbuf_make()` */
#define CBUF_MAX_CAPACITY SSIZE_MAX

/**
 * @struct cbuf_t
 * @brief Lock-free single-producer single-consumer (SPSC) circular buffer.
 *
 * A circular (ring) buffer designed for concurrent read and write access by one
 * reader and one writer thread.
 *
 * - Thread-safe for concurrent use by one reader and one writer thread, NOT
 * safe for multiple synchronouse readers/writers.
 *
 * - `readp` and `writep` are atomic pointers that "chase" each other. Readable
 * data is available between `readp` and `writep`. The buffer is considered full
 * when advancing the write pointer would cause it to equal the read pointer
 * (one byte is always left unused). The buffer is considered empty when `readp
 * == writep`.
 */
typedef struct cbuf_st {
  uint8_t *restrict buf;
  _Atomic(uint8_t *) readp;
  _Atomic(uint8_t *) writep;
  size_t capacity;
} cbuf_t;

int cbuf_init(cbuf_t *cbuf, size_t capacity);

void cbuf_free(cbuf_t *cbuf);

int cbuf_make(cbuf_t *cbuf, uint8_t *buf, size_t len);

size_t cbuf_release(cbuf_t *cbuf, uint8_t **buf);

size_t cbuf_get_capacity(cbuf_t *cbuf);

int cbuf_is_empty(cbuf_t *cbuf);

int cbuf_is_full(cbuf_t *cbuf);

ssize_t cbuf_get_readable_size(cbuf_t *cbuf);

int cbuf_waitfor_readable(cbuf_t *cbuf, size_t nbytes, int64_t timeout_msec);

ssize_t cbuf_write_blocking(cbuf_t *cbuf, const uint8_t *buf, size_t nbytes,
                            int64_t timeout_msec);

ssize_t cbuf_read_blocking(cbuf_t *cbuf, uint8_t *buf, size_t nbytes,
                           int64_t timeout_msec, bool all);

ssize_t cbuf_peek(cbuf_t *cbuf, uint8_t *buf, size_t nbytes);

ssize_t cbuf_remove(cbuf_t *cbuf, size_t nbytes);
