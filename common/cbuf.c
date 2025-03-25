#include "cbuf.h"
#include "time_utils.h"

#include <time.h>

/**
 * @param[in] cbuf The cbuf to initialize.
 * @param[in] capacity The capacity in bytes.
 * @return 0 on success, -1 on failure.
 *
 * @brief Allocate memory for a cbuf.
 */
int cbuf_init(cbuf_t *cbuf, size_t capacity) {
  if (!cbuf)
    return -1;

  if ((capacity < CBUF_MIN_CAPACITY) || (capacity > CBUF_MAX_CAPACITY))
    return -1;

  cbuf->buf = zt_malloc(capacity);
  if (!cbuf->buf)
    return -1;

  cbuf->capacity = capacity;
  atomic_init(&cbuf->readp, cbuf->buf);
  atomic_init(&cbuf->writep, cbuf->buf);

  return 0;
}

/**
 * @param[in] cbuf The cbuf to free
 *
 * @brief Free the memory allocated for @p cbuf.
 */
void cbuf_free(cbuf_t *cbuf) {
  if (!cbuf)
    return;

  cbuf->capacity = 0;
  atomic_store(&cbuf->readp, NULL);
  atomic_store(&cbuf->writep, NULL);
  zt_free(cbuf->buf);
}

/**
 * @param[in] cbuf An uninitialized cbuf instance.
 * @param[in] buf The buffer to use.
 * @param[in] len The length of the buffer.
 * @return 0 on success, -1 for invalid arguments.
 *
 * @brief Initialize a @p cbuf with an existing buffer.
 *
 * - `CBUF_MIN_CAPACITY <= len <= CBUF_MAX_CAPACITY`
 *
 * - The ownership of the pointer @p buf is transferred to @p cbuf. If @p buf is
 * accessed externally, the behavior is undefined.
 *
 * - To release this buffer for external use again, use `cbuf_release()`.
 */
int cbuf_make(cbuf_t *cbuf, uint8_t *buf, size_t len) {
  if (!cbuf || !buf || (len < CBUF_MIN_CAPACITY) || (len > CBUF_MAX_CAPACITY))
    return -1;

  cbuf->buf = buf;
  cbuf->capacity = len;
  atomic_init(&cbuf->readp, cbuf->buf);
  atomic_init(&cbuf->writep, cbuf->buf);

  return 0;
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @param[out] buf The pointer to the released buffer.
 * @return The capacity of @p *buf.
 *
 * @brief Release the buffer from @p cbuf for external use. This function will
 * transfer ownership of internal buffer of this @p cbuf to the caller.
 *
 * After calling this function,
 *
 * - The caller is responsible for freeing (if necessary) this buffer.
 *
 * - This @p cbuf CANNOT be used before calling `cbuf_make()` or `cbuf_init()`.
 */
size_t cbuf_release(cbuf_t *cbuf, uint8_t **buf) {
  if (!cbuf || !buf)
    return 0;

  *buf = cbuf->buf;
  cbuf->capacity = 0;
  atomic_store(&cbuf->readp, NULL);
  atomic_store(&cbuf->writep, NULL);

  return cbuf->capacity;
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @return The capacity of @p cbuf.
 *
 * @brief Get the write capacity of @p cbuf.
 */
size_t cbuf_get_capacity(cbuf_t *cbuf) {
  if (unlikely(!cbuf))
    return 0;

  return cbuf->capacity - 1;
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @return >0 if the buffer is empty, 0 if @p cbuf is not empty,
 * -1 for invalid arguments.
 *
 * @brief Check if the buffer is empty.
 */
int cbuf_is_empty(cbuf_t *cbuf) {
  uint8_t *readp, *writep;

  if (unlikely(!cbuf))
    return -1;

  readp = atomic_load_explicit(&cbuf->readp, memory_order_acquire);
  writep = atomic_load_explicit(&cbuf->writep, memory_order_acquire);

  return readp == writep;
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @return >0 if the buffer is full, 0 if @p cbuf is not full,
 * -1 for invalid arguments.
 *
 * @brief Check if the buffer is full.
 */
int cbuf_is_full(cbuf_t *cbuf) {
  uint8_t *writep, *readp;
  ssize_t offs;

  if (unlikely(!cbuf))
    return -1;

  readp = atomic_load_explicit(&cbuf->readp, memory_order_acquire);
  writep = atomic_load_explicit(&cbuf->writep, memory_order_acquire);

  if (readp <= writep)
    offs = writep - readp;
  else
    offs = cbuf->capacity - (ssize_t)(readp - writep);

  return offs == cbuf->capacity - 1;
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @return The number of bytes available to read, or -1 for invalid arguments.
 *
 * @brief Get the number of bytes available to read from @p cbuf.
 */
ssize_t cbuf_get_readable_size(cbuf_t *cbuf) {
  uint8_t *writep, *readp;
  ssize_t offs;

  if (unlikely(!cbuf))
    return 0;

  readp = atomic_load_explicit(&cbuf->readp, memory_order_acquire);
  writep = atomic_load_explicit(&cbuf->writep, memory_order_acquire);
  if (readp <= writep)
    offs = writep - readp;
  else
    offs = cbuf->capacity - (ssize_t)(readp - writep);

  return offs;
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @param[in] nbytes The number of bytes that must become readable.
 * @param[in] timeout_msec The wait timeout (in ms).
 * @return >0 if @p nbytes are readable, 0 if the timeout expired,
 * -1 for invalid arguments.
 *
 * @brief Wait for at most @p timeout_msec ms for @p nbytes to become readable
 * in @p cbuf.
 *
 * The following values of @p timeout_msec are special:
 *
 * - `0`: return immediately
 *
 * - `-1`: wait indefinitely
 */
int cbuf_waitfor_readable(cbuf_t *cbuf, size_t nbytes,
                          timediff_t timeout_msec) {
  zt_timeout_t timeout;
  // 800us sleep
  const struct timespec sleep_timeout = {.tv_sec = 0, .tv_nsec = 800 * 1000};

  if (!cbuf || !nbytes)
    return -1;

  zt_timeout_begin(&timeout, timeout_msec * 1000, NULL);
  for (;;) {
    if (cbuf_get_readable_size(cbuf) >= nbytes)
      return 1;

    if (zt_timeout_expired(&timeout, NULL))
      return 0;

    clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_timeout, NULL);
  }
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @param[in] buf The buffer to write.
 * @param[in] nbytes The maximum number of bytes to write.
 * @param[in] timeout_msec The wait timeout (in ms).
 * @return The number of bytes written, or -1 for invalid arguments.
 *
 * @brief Lock-free blocking write for this SPSC @p cbuf.
 * This function will block using busy-waiting until some space becomes
 * available or @p timeout_msec ms have elapsed. Once any amount of free space
 * is available to write, the function writes as much as possible and returns
 * the number of bytes written.
 *
 * The following values of @p timeout_msec are special:
 *
 * - `0`: return immediately
 *
 * - `-1`: wait indefinitely
 */
ssize_t cbuf_write_blocking(cbuf_t *cbuf, const uint8_t *buf, size_t nbytes,
                            timediff_t timout_msec) {
  uint8_t *writep, *readp;
  ssize_t capacity, nwrite, len, rem;
  zt_timeout_t timeout;
  // 800us sleep
  const struct timespec sleep_timeout = {.tv_sec = 0, .tv_nsec = 800 * 1000};

  if (!cbuf || !buf || (nbytes > cbuf->capacity))
    return -1;

  capacity = cbuf->capacity;

  /* Start the timeout and spin until there is space to write */
  zt_timeout_begin(&timeout, timout_msec * 1000, NULL);
  for (;;) {
    readp = atomic_load_explicit(&cbuf->readp, memory_order_acquire);
    /* Since only the writer updates writep, a plain load is OK */
    writep = atomic_load_explicit(&cbuf->writep, memory_order_relaxed);

    /**
     * Scenario 1:
     * buf[      r................w        ]buf+capacity
     *
     * Scenario 2:
     * buf[......w                r........]buf+capacity
     *
     * Calculate available free space; reserve one space
     * to distinguish between full and empty.
     */
    if (writep >= readp)
      nwrite = capacity - (ssize_t)(writep - readp) - 1;
    else
      nwrite = (ssize_t)(readp - writep) - 1;

    if (nwrite > 0)
      break; /* we have some space to write */

    if (zt_timeout_expired(&timeout, NULL))
      return 0; /* timed out with no free space */

    clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_timeout, NULL);
  }

  ASSERT(nwrite > 0);
  nwrite = MIN(nbytes, nwrite);

  /* Two-phase copy; write up to the end of the buffer */
  len = (ssize_t)(cbuf->buf + capacity - writep);
  len = MIN(len, nwrite);
  zt_memcpy(writep, buf, len);

  rem = nwrite - len;
  /* If necessary, wrap around and write from the beginning */
  if (rem) {
    zt_memcpy(cbuf->buf, buf + len, rem);
    writep = cbuf->buf + rem;
  } else {
    writep += len;
    if (writep == (cbuf->buf + capacity))
      writep = cbuf->buf;
  }

  atomic_store_explicit(&cbuf->writep, writep, memory_order_release);
  return nwrite;
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @param[out] buf The buffer to read into.
 * @param[in] nbytes The maximum number of bytes to read.
 * @param[in] timeout_msec The wait timeout (in ms).
 * @param[in] all Enforce all-or-nothing behaviour.
 * @return The number of bytes read into @p buf, or -1 for invalid arguments.
 *
 * @brief Lock-free blocking read for this SPSC @p cbuf. This function will
 * block for at most @p timeout_msec ms using busy-waiting until @p nbytes are
 * readable. Data is read with FIFO ordering.
 *
 * - If @p all is set to `true`, the function will read exactly @p nbytes bytes
 * from @p cbuf. If there are not enough bytest to read, the function returns 0;
 * Otherwise, it returns @p nbytes.
 *
 * - If @p all is set to `false`, the function will wait no longer than
 * @p timeout_msec ms until @p nbytes are available to read. If the timeout
 * expires before the data becomes available, the function reads whatever bytes
 * are available and returns the number of bytes read.
 *
 * The following values of @p timeout_msec are special:
 *
 * - `0`: return immediately
 *
 * - `-1`: wait indefinitely
 */
ssize_t cbuf_read_blocking(cbuf_t *cbuf, uint8_t *buf, size_t nbytes,
                           timediff_t timeout_msec, bool all) {
  uint8_t *writep, *readp;
  ssize_t capacity, nread, len, rem;
  zt_timeout_t timeout;
  // 800us sleep
  const struct timespec sleep_timeout = {.tv_sec = 0, .tv_nsec = 800 * 1000};

  if (!cbuf || !buf || (nbytes > cbuf->capacity))
    return -1;

  capacity = cbuf->capacity;

  /* spinlock */
  zt_timeout_begin(&timeout, timeout_msec * 1000, NULL);
  for (;;) {
    readp = atomic_load_explicit(&cbuf->readp, memory_order_acquire);
    writep = atomic_load_explicit(&cbuf->writep, memory_order_acquire);

    /* empty condition => readp == writep */
    if (readp <= writep)
      nread = (ssize_t)(writep - readp);
    else
      nread = capacity - (ssize_t)(readp - writep);

    if (nread >= nbytes)
      break;

    if (zt_timeout_expired(&timeout, NULL))
      break;

    clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_timeout, NULL);
  }

  if (nread <= 0)
    return 0;
  if (all && (nread < nbytes))
    return 0;

  nread = MIN(nbytes, nread);

  /* Read up to the end of the buffer */
  len = (ssize_t)(cbuf->buf + capacity - readp);
  len = MIN(len, nread);
  zt_memcpy(buf, readp, len);

  rem = nread - len;
  /* If necessary, wrap around and read from the beginning of the buffer */
  if (rem) {
    zt_memcpy(buf + len, cbuf->buf, rem);
    readp = cbuf->buf + rem;
  } else {
    readp += len;
    if (readp == (cbuf->buf + capacity))
      readp = cbuf->buf;
  }

  atomic_store_explicit(&cbuf->readp, readp, memory_order_release);
  return nread;
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @param[out] buf The buffer to read into.
 * @param[in] nbytes The size of the @p buf.
 * @return The number of bytes read, or -1 for invalid arguments.
 *
 * @brief Read data from @p cbuf into @p buf without consuming it.
 * Data is read with FIFO ordering.
 */
ssize_t cbuf_peek(cbuf_t *cbuf, uint8_t *buf, size_t nbytes) {
  uint8_t *readp, *writep;
  ssize_t nread, capacity, len, rem;

  if (!cbuf || !buf)
    return -1;

  capacity = cbuf->capacity;
  readp = atomic_load_explicit(&cbuf->readp, memory_order_acquire);
  writep = atomic_load_explicit(&cbuf->writep, memory_order_acquire);

  if (readp <= writep)
    nread = (ssize_t)(writep - readp);
  else
    nread = capacity - (ssize_t)(readp - writep);
  nread = MIN(nread, nbytes);

  len = (ssize_t)(cbuf->buf + capacity - readp);
  len = MIN(len, nread);
  zt_memcpy(buf, readp, len);

  rem = nread - len;
  if (rem)
    zt_memcpy(buf + len, cbuf->buf, rem);

  return nread;
}

/**
 * @param[in] cbuf An initialized cbuf instance. See `cbuf_init()` and
 * `cbuf_make()`.
 * @param[in] nbytes The maximum number of bytes to delete.
 * @return The number of bytes deleted, or -1 for invalid arguments.
 *
 * @brief Delete no more than @p nbytes bytes from the @p cbuf in FIFO order.
 */
ssize_t cbuf_remove(cbuf_t *cbuf, size_t nbytes) {
  uint8_t *readp, *writep;
  ssize_t n;

  if (!cbuf)
    return -1;

  readp = atomic_load_explicit(&cbuf->readp, memory_order_acquire);
  writep = atomic_load_explicit(&cbuf->writep, memory_order_acquire);

  n = MIN(cbuf_get_readable_size(cbuf), nbytes);
  readp = cbuf->buf + (readp - cbuf->buf + n) % cbuf->capacity;

  atomic_store_explicit(&cbuf->readp, readp, memory_order_release);
  return n;
}
