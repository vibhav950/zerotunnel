#include "io.h"

#include "errno.h"
#include <poll.h>

/**
 * @param[in] fd The file descriptor to wait for.
 * @param[in] timeout_msec The wait timeout in milliseconds.
 * @param[in] mode `ZT_NETIO_READABLE`, `ZT_NETIO_WRITABLE` or the bitwise OR of
 * the two.
 * @return -1 on error or timeout, otherwise check for the bitwise OR of
 * `ZT_NETIO_READABLE` and `ZT_NETIO_WRITABLE`.
 *
 * Wait for the file descriptor to become readable/writable.
 *
 * Following values of @p timeout_msec are special:
 * If `0`, the function will return immediately.
 * If `-1`, the function will wait indefinitely.
 */
int zt_io_waitfor(int fd, timediff_t timeout_msec, int mode) {
  int rc = -1;
  struct pollfd pollfd;

  pollfd.fd = fd;
  pollfd.events = 0;  // events to poll for (in)
  pollfd.revents = 0; // events that occurred (out)

  if (mode & ZT_IO_READABLE)
    pollfd.events |= POLLIN;
  if (mode & ZT_IO_WRITABLE)
    pollfd.events |= POLLOUT;

  if ((rc = poll(&pollfd, 1, timeout_msec)) > 0) {
    rc = 0;
    if (pollfd.revents & POLLIN)
      rc |= ZT_IO_READABLE;
    if (pollfd.revents & POLLOUT)
      rc |= ZT_IO_WRITABLE;
  } else if (rc == 0) {
    PRINTERROR("Connection timed out\n");
    return -1;
  } else {
    PRINTERROR("poll(2) failed (%s)\n", strerror(errno));
    return -1;
  }

  return rc;
}

/**
 * @param[in] fd The file descriptor to wait for.
 * @param[in] timeout_msec The wait timeout in milliseconds.
 * @return `true` if the file descriptor is readable, `false` otherwise.
 *
 * Wait for a file descriptor to become readable.
 *
 * Following values of @p timeout_msec are special:
 * If `0`, the function will return immediately.
 * If `-1`, the function will wait indefinitely.
 */
bool zt_io_waitfor_read(int fd, timediff_t timeout_msec) {
  return zt_io_waitfor(fd, timeout_msec, ZT_IO_READABLE) > 0;
}

/**
 * @param[in] fd The file descriptor to wait for.
 * @param[in] timeout_msec The wait timeout in milliseconds.
 * @return `true` if the file descriptor is writable, `false` otherwise.
 *
 * Wait for a file descriptor to become writable.
 *
 * Following values of @p timeout_msec are special:
 * If `0`, the function will return immediately.
 * If `-1`, the function will wait indefinitely.
 */
bool zt_io_waitfor_write(int fd, timediff_t timeout_msec) {
  return zt_io_waitfor(fd, timeout_msec, ZT_IO_WRITABLE) > 0;
}
