#include "io.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif

static inline int zt_io_waitfor1(int fd, timediff_t timeout_msec, int mode) {
  int rc = -1;
  struct pollfd pollfd;

  pollfd.fd = fd;
  pollfd.events = 0;  /* events to poll for (in) */
  pollfd.revents = 0; /* events that occurred (out) */

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

#ifdef USE_EPOLL
static inline int zt_io_waitfor2(int fd, timediff_t timeout_msec, int mode) {
  struct epoll_event ev, events[1];
  int epfd, rc = -1;

  epfd = epoll_create1(0);
  if (epfd == -1) {
    PRINTERROR("epoll_create1(2) failed (%s)\n", strerror(errno));
    return -1;
  }

  ev.data.fd = fd;
  ev.events = 0;

  if (mode & ZT_IO_READABLE)
    ev.events |= EPOLLIN;
  if (mode & ZT_IO_WRITABLE)
    ev.events |= EPOLLOUT;

  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    PRINTERROR("epoll_ctl(2) failed (%s)\n", strerror(errno));
    goto cleanup;
  }

  if ((rc = epoll_wait(epfd, events, 1, timeout_msec)) > 0) {
    rc = 0;
    if (events[0].events & EPOLLIN)
      rc |= ZT_IO_READABLE;
    if (events[0].events & EPOLLOUT)
      rc |= ZT_IO_WRITABLE;
  } else if (rc == 0) {
    PRINTERROR("Connection timed out\n");
    rc = -1;
  } else {
    PRINTERROR("epoll_wait(2) failed (%s)\n", strerror(errno));
    rc = -1;
  }

cleanup:
  close(epfd);
  return rc;
}
#endif /* USE_EPOLL */

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
#ifdef USE_EPOLL
  return zt_io_waitfor2(fd, timeout_msec, mode);
#else
  return zt_io_waitfor1(fd, timeout_msec, mode);
#endif
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

/**
 * @param[in] name The name of the file to delete.
 * @return An `error_t` status code.
 *
 * Delete a file.
 */
error_t zt_file_delete(const char *name) {
  if (unlink(name) == -1) {
    PRINTERROR("failed to unlink(2) file %s (%s)", name, strerror(errno));
    return ERR_INVALID;
  }
  return ERR_SUCCESS;
}

/**
 * @param[in] name The name of the file to delete.
 * @return An `error_t` status code.
 *
 * Zero out and delete a file.
 */
error_t zt_file_zdelete(const char *name) {
  int fd = open(name, O_WRONLY);
  if (fd == -1) {
    PRINTERROR("failed to open(2) file %s (%s)", name, strerror(errno));
    return ERR_INVALID;
  }
  fzero(fd);
  close(fd);
  if (unlink(name) == -1) {
    PRINTERROR("failed to unlink(2) file %s (%s)", name, strerror(errno));
    return ERR_INVALID;
  }
  return ERR_SUCCESS;
}

/**
 * @param[in] name The name of the file to rename.
 * @param[in] new_name The new name of the file.
 * @return An `error_t` status code.
 *
 * Rename a file.
 */
error_t zt_file_rename(const char *name, const char *new_name) {
  if (rename(name, new_name) != 0) {
    PRINTERROR("failed to rename(3) %s to %s (%s)", name, new_name,
               strerror(errno));
    return ERR_INVALID;
  }
  return ERR_SUCCESS;
}

/**
 * @param[in] fio An open file descriptor.
 * @return The size of the file in bytes or -1 on error.
 *
 * Get the size of the file represented by an open file descriptor.
 */
off_t zt_file_getsize(int fd) {
  struct stat st;

  if (likely(fd > 2)) {
    if (likely(fstat(fd, &st) == 0)) {
      if (S_ISREG(st.st_mode)) {
        return st.st_size;
      } else if (S_ISBLK(st.st_mode)) {
        uint64_t bytes = 0;
        if (likely(ioctl(fd, BLKGETSIZE64, &bytes) == 0))
          return bytes;
      }
    }
  }
  return -1;
}

/** How far past the page boundary is `offs` */
#define PA_OVERSHOOT(offs) ((offs) & (sysconf(_SC_PAGE_SIZE) - 1))

/** Rounded-up page-aligned size */
#define PA_SIZE(size) ((((size) - 1) | (sysconf(_SC_PAGE_SIZE) - 1)) + 1)

#define FIO_FL_TST(fio, flgs) ((fio->flags & (flgs)) == (flgs))
#define FIO_FL_SET(fio, flag) (fio->flags |= (flag))
#define FIO_FL_CLR(fio, flag) (fio->flags &= ~(flag))

/**
 * @param[in] fio An fio structure to be initialized.
 * @param[in] name The path of the file to open.
 * @param[in] mode The mode in which to open the file.
 * @return An `error_t` status code.
 *
 * Open a file in the specified mode. The caller must call `zt_fio_close()`
 * on this @p fio after use.
 */
error_t zt_fio_open(zt_fio_t *fio, const char *name, zt_fio_mode_t mode) {
  int fd = -1;
  int flags = 0;
  off_t size;

  if (unlikely(!fio || !name))
    return ERR_NULL_PTR;

  switch (mode) {
  case FIO_RDONLY:
    flags = O_RDONLY;
    break;
  case FIO_RDWR:
    flags = O_RDWR;
    break;
  case FIO_WRONLY:
    flags = O_WRONLY;
    break;
  case FIO_APPEND:
    flags = O_WRONLY | O_APPEND;
    break;
  case FIO_RDAPPEND:
    flags = O_RDWR | O_APPEND;
    break;
  default:
    return ERR_BAD_ARGS;
  }

  if (mode == FIO_RDONLY)
    fd = open(name, flags);
  else
    fd = open(name, flags | O_CREAT, 0600);

  if (fd == -1) {
    PRINTERROR("failed to open(2) file %s (%s)", name, strerror(errno));
    return ERR_BAD_ARGS;
  }

  size = zt_file_getsize(fd);

  zt_memzero(fio, sizeof(zt_fio_t));

  fio->fd = fd;
  fio->size = size;
  fio->name = zt_strdup(name);

  FIO_FL_SET(fio, FIO_FL_OPEN);

  /** Set the operation access flags */
  if (mode == FIO_RDONLY)
    FIO_FL_SET(fio, FIO_FL_READ);
  else if (mode == FIO_WRONLY)
    FIO_FL_SET(fio, FIO_FL_WRITE);
  else
    FIO_FL_SET(fio, FIO_FL_READ | FIO_FL_WRITE);

  /** Set the `mmap()` chunk size for reads, depending on the file size */
  if (size >= 4 * SIZE_GB) {
    FIO_FL_SET(fio, FIO_FL_XXL);
    fio->_pa_chunk_size = FIO_CHUNK_SIZE_XXL;
  } else if (size >= 512 * SIZE_MB) {
    FIO_FL_SET(fio, FIO_FL_XL);
    fio->_pa_chunk_size = FIO_CHUNK_SIZE_XL;
  } else {
    fio->_pa_chunk_size = MIN(PA_SIZE(fio->size), FIO_CHUNK_SIZE_XL);
  }

  return ERR_SUCCESS;
}

/**
 * @param[in] fio An open fio.
 * @return Void.
 *
 * De-init the fio and close the underlying file descriptor.
 */
void zt_fio_close(zt_fio_t *fio) {
  if (likely((fio != NULL) && FIO_FL_TST(fio, FIO_FL_OPEN))) {
    if (fio->_prev)
      munmap(fio->_prev, fio->_prevsize);
    close(fio->fd);
    zt_free(fio->name);
    zt_memzero(fio, sizeof(zt_fio_t));
    fio->fd = -1;
  }
}

/**
 * @param[in] fio An open fio. See `zt_fio_open()`.
 * @param[out] buf A pointer to a pointer to the buffer with the data read.
 * @param[out] bufsize The number of readable bytes placed in @p *buf.
 * @return An `error_t` status code.
 *
 * Reads a portion of the underlying file using a sliding window fashion.
 *
 * This function provides sequential read access to a file by `mmap()`ing fixed
 * size page-aligned chunks into the address space of this process. The Each
 * call to `zt_fio_read()` advances the read window, `munmap()`ing the previous
 * region and `mmap()`ing the next one.
 *
 * `zt_fio_close()` will perform the required `munmap()` on the final chunk.
 */
error_t zt_fio_read(zt_fio_t *fio, void **buf, size_t *bufsize) {
  int fd, flags;
  void *maddr;
  off_t size, offset;
  size_t pa_size;

  if (unlikely(!fio || !buf || !bufsize))
    return ERR_NULL_PTR;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_READ)))
    return ERR_INVALID;

  if (likely(fio->_prev)) {
    munmap(fio->_prev, fio->_prevsize);
    fio->_prev = NULL;
  }

  if (fio->offset >= fio->size)
    return ERR_EOF;

  fd = fio->fd;
  flags = fio->flags;
  size = fio->size;
  offset = fio->offset;
  pa_size = MIN(fio->_pa_chunk_size, PA_SIZE(size - offset));

  maddr = mmap(NULL, pa_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, offset);
  if (maddr == MAP_FAILED) {
    PRINTERROR("failed to mmap(2) file %s (%s)", fio->name, strerror(errno));
    return ERR_FIO_READ;
  }

  madvise(maddr, pa_size, MADV_WILLNEED);

  fio->_prev = maddr;
  fio->_prevsize = pa_size;
  fio->offset += pa_size;

  *buf = maddr;

  if (likely(pa_size < size))
    *bufsize = MIN(pa_size, size - offset);
  else
    *bufsize = size;

  return ERR_SUCCESS;
}

/*
error_t zt_fio_read(zt_fio_t *fio, void *buf, size_t bufsize, size_t *nread) {
  ssize_t rc;

  if (unlikely(!fio || !buf || !nread))
    return ERR_NULL_PTR;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_READ)))
    return ERR_INVALID;

  rc = read(fio->fd, buf, bufsize);
  switch (rc) {
    case -1:
      PRINTERROR("failed to read(2) from file %s (%s)", fio->name,
                 strerror(errno));
      return ERR_FIO_READ;
    case 0:
      *nread = 0;
      return ERR_EOF;
    default:
      *nread = rc;
      break;
  }
  fio->offset += rc;

  return ERR_SUCCESS;
}
*/

/**
 * @param[in] fio An open fio. See `zt_fio_open()`.
 * @param[in] buf A pointer to the buffer with data to write.
 * @param[in] bufsize The number of bytes to write.
 * @return An `error_t` status code.
 *
 * Writes @p bufsize bytes from @p buf to the file represented by @p fio.
 * Partial writes are treated as errors.
 */
error_t zt_fio_write(zt_fio_t *fio, const void *buf, size_t bufsize) {
  ssize_t rc;

  if (unlikely(!fio || !buf))
    return ERR_NULL_PTR;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_WRITE)))
    return ERR_INVALID;

  rc = write(fio->fd, buf, bufsize);
  if (rc != bufsize) {
    PRINTERROR("failed to write(2) to file %s (%s)", fio->name,
               strerror(errno));
    return ERR_FIO_WRITE;
  }

  fio->offset += rc;
  return ERR_SUCCESS;
}
