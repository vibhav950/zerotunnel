/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * io.c - I/O and file operations
 */

#include "io.h"
#include "common/log.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <linux/fs.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_EPOLL
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

  rc = 0;
  if ((rc = poll(&pollfd, 1, timeout_msec)) > 0) {
    if (pollfd.revents & POLLIN)
      rc |= ZT_IO_READABLE;
    if (pollfd.revents & POLLOUT)
      rc |= ZT_IO_WRITABLE;
  } else if (rc == 0) {
    log_error(NULL, "Connection timed out");
    return 0;
  } else {
    log_error(NULL, "poll: Failed (%s)", strerror(errno));
    return -1;
  }
  return rc;
}

#ifdef HAVE_EPOLL
static inline int zt_io_waitfor2(int fd, timediff_t timeout_msec, int mode) {
  struct epoll_event ev, events[1];
  int epfd, rc = -1;

  epfd = epoll_create1(0);
  if (epfd == -1) {
    log_error(NULL, "epoll_create1: Failed (%s)", strerror(errno));
    return -1;
  }

  ev.data.fd = fd;
  ev.events = 0;

  if (mode & ZT_IO_READABLE)
    ev.events |= EPOLLIN;
  if (mode & ZT_IO_WRITABLE)
    ev.events |= EPOLLOUT;

  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    log_error(NULL, "epoll_ctl: Failed (%s)", strerror(errno));
    goto cleanup;
  }

  rc = 0;
  if ((rc = epoll_wait(epfd, events, 1, timeout_msec)) > 0) {
    if (events[0].events & EPOLLIN)
      rc |= ZT_IO_READABLE;
    if (events[0].events & EPOLLOUT)
      rc |= ZT_IO_WRITABLE;
  } else if (rc == 0) {
    log_error(NULL, "Connection timed out");
  } else {
    log_error(NULL, "epoll_wait: Failed (%s)", strerror(errno));
    rc = -1;
  }

cleanup:
  close(epfd);
  return rc;
}
#endif /* HAVE_EPOLL */

/**
 * @param[in] fd The file descriptor to wait for.
 * @param[in] timeout_msec The wait timeout in milliseconds.
 * @param[in] mode `ZT_NETIO_READABLE`, `ZT_NETIO_WRITABLE` or the bitwise OR of
 * the two.
 * @return -1 on error, 0 on timeout, otherwise check for the bitwise OR of
 * `ZT_NETIO_READABLE` and `ZT_NETIO_WRITABLE`.
 *
 * Wait for the file descriptor to become readable/writable.
 *
 * Following values of @p timeout_msec are special:
 * If `0`, the function will return immediately.
 * If `-1`, the function will wait indefinitely.
 */
int zt_io_waitfor(int fd, timediff_t timeout_msec, int mode) {
#ifdef HAVE_EPOLL
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
 * @param[in] filepath The path of the file to delete.
 * @return An `err_t` status code.
 *
 * Delete a file.
 */
err_t zt_file_delete(const char *filepath) {
  if (unlink(filepath) == -1) {
    log_error(NULL, "Failed to unlink file '%s' (%s)", filepath, strerror(errno));
    return ERR_INVALID;
  }
  return ERR_SUCCESS;
}

/**
 * @param[in] filepath The path of the file to delete.
 * @return An `err_t` status code.
 *
 * Zero out and delete a file.
 */
err_t zt_file_zdelete(const char *filepath) {
  int fd = open(filepath, O_WRONLY);
  if (fd == -1) {
    log_error(NULL, "Failed to open file '%s' (%s)", filepath, strerror(errno));
    return ERR_INVALID;
  }
  fzero(fd);
  close(fd);
  if (unlink(filepath) == -1) {
    log_error(NULL, "Failed to unlink file '%s' (%s)", filepath, strerror(errno));
    return ERR_INVALID;
  }
  return ERR_SUCCESS;
}

/**
 * @param[in] oldpath The path of the file to rename.
 * @param[in] newpath The new path of the file.
 * @return An `err_t` status code.
 *
 * Rename a file.
 */
err_t zt_file_rename(const char *oldpath, const char *newpath) {
  struct stat st;
  char *p;

  /** oldpath may not be a directory */
  stat(oldpath, &st);
  if (!S_ISREG(st.st_mode))
    return ERR_BAD_ARGS;

  if (!(p = zt_strdup(newpath)))
    return ERR_MEM_FAIL;

  /** newpath may not be a directory */
  p = basename(p);
  if ((p[0] == '/') || ((p[0] == '.') && (p[1] == '\0')) ||
      ((p[0] == '.') && (p[1] == '.') && (p[2] == '\0'))) {
    return ERR_BAD_ARGS;
  }

  if (rename(oldpath, newpath) != 0) {
    log_error(NULL, "Failed to rename '%s' to '%s' (%s)", oldpath, newpath,
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

static inline void ATTRIBUTE_NONNULL(1) _reset_fio(zt_fio_t *fio) {
  ASSERT(fio);

  fio->fd = -1;
  fio->path = NULL;
  fio->flags = 0;
  fio->size = 0;
  fio->offset = 0;
  // fio->_prev = NULL;
  // fio->_prevsize = 0;
  // fio->_pa_chunk_size = 0;
}

/**
 * @param[in] fio An fio structure to be initialized.
 * @param[in] filepath The path of the file to open.
 * @param[in] mode The mode in which to open the file.
 * @return An `err_t` status code.
 *
 * Open a file in the specified mode. The caller must call `zt_fio_close()`
 * on this @p fio after use.
 *
 * If @p filepath is "-", then @p fio will be initialized to use the standard
 * input/output depending on @p mode. In this case, the only supported modes
 * are FIO_RDONLY, FIO_WRONLY, and FIO_APPEND.
 *
 * This function will put an exclusive lock on the file if @p mode is one
 * of the writable modes - FIO_RDWR, FIO_WRONLY, FIO_APPEND, FIO_RDAPPEND.
 * If the file is opened in read-only mode (FIO_RDONLY), a shared lock is
 * acquired instead.
 */
err_t zt_fio_open(zt_fio_t *fio, const char *filepath, zt_fio_mode_t mode) {
  int fd = -1;
  int flags = 0;
  off_t size;
  struct flock fl;

  if (!fio || !filepath)
    return ERR_NULL_PTR;

  _reset_fio(fio);

  if (!strcmp(filepath, "-")) {
    switch (mode) {
    case FIO_RDONLY:
      fd = STDIN_FILENO;
      flags = FIO_FL_READ;
      break;
    case FIO_WRONLY:
    case FIO_APPEND:
      fd = STDOUT_FILENO;
      flags = FIO_FL_WRITE;
      break;
    default:
      return ERR_BAD_ARGS;
    }
    fio->fd = fd;
    FIO_FL_SET(fio, FIO_FL_OPEN | flags);
    return ERR_SUCCESS;
  }

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
    fd = open(filepath, flags);
  else
    fd = open(filepath, flags | O_CREAT, 0600);

  if (fd == -1) {
    log_error(NULL, "Failed to open file '%s' (%s)", filepath, strerror(errno));
    return ERR_BAD_ARGS;
  }

  /** Lock the file */
  fl.l_type = (mode == FIO_RDONLY) ? F_RDLCK : F_WRLCK;
  fl.l_start = 0;
  fl.l_whence = SEEK_SET;
  fl.l_len = 0; /* entire file */
  if (fcntl(fd, F_SETLK, &fl) < 0) {
    log_error(NULL, "fcntl: Failed to lock file '%s' (%s)", filepath, strerror(errno));
    close(fd);
    return ERR_BAD_ARGS;
  }

  size = zt_file_getsize(fd);

  fio->fd = fd;
  fio->size = size;
  fio->path = zt_strdup(filepath);
  FIO_FL_SET(fio, FIO_FL_OPEN);

  /** Set the operation access flags */
  if (mode == FIO_RDONLY)
    FIO_FL_SET(fio, FIO_FL_READ);
  else if (mode == FIO_WRONLY)
    FIO_FL_SET(fio, FIO_FL_WRITE);
  else
    FIO_FL_SET(fio, FIO_FL_READ | FIO_FL_WRITE);

  // /** Set the `mmap()` chunk size for reads, depending on the file size */
  // if (size >= 4 * SIZE_GB) {
  //   FIO_FL_SET(fio, FIO_FL_XXL);
  //   fio->_pa_chunk_size = FIO_CHUNK_SIZE_XXL;
  // } else if (size >= 512 * SIZE_MB) {
  //   FIO_FL_SET(fio, FIO_FL_XL);
  //   fio->_pa_chunk_size = FIO_CHUNK_SIZE_XL;
  // } else {
  //   fio->_pa_chunk_size = MIN(PA_SIZE(fio->size), FIO_CHUNK_SIZE_XL);
  // }

  return ERR_SUCCESS;
}

/**
 * @param[in] fio An open fio.
 * @return Void.
 *
 * De-init the fio, unlock and close the underlying file descriptor.
 */
void zt_fio_close(zt_fio_t *fio) {
  struct flock fl;

  if (fio && FIO_FL_TST(fio, FIO_FL_OPEN)) {
    // if (fio->_prev)
    // munmap(fio->_prev, fio->_prevsize);
    if (fio->fd >= 3) {
      fl.l_type = F_UNLCK;
      fl.l_whence = SEEK_SET;
      fl.l_start = 0;
      fl.l_len = 0; /* entire file */
      (void)fcntl(fio->fd, F_SETLK, &fl);
      close(fio->fd);
      zt_free(fio->path);
    }
    _reset_fio(fio);
  }
}

/**
 * @param[in] fio An open fio. See `zt_fio_open()`.
 * @param[out] info The file info pointer.
 * @return An `err_t` status code.
 *
 * Get the file information for the file represented by the `fio`.
 */
err_t zt_fio_fileinfo(zt_fio_t *fio, zt_fileinfo_t *info) {
  char *p;

  if (unlikely(!fio || !info))
    return ERR_NULL_PTR;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN)))
    return ERR_BAD_ARGS;

  if (fio->fd >= 3) {
    p = basename(fio->path);
    /** Sanity check; this should never happen with an open fio */
    if (unlikely((p[0] == '/') || ((p[0] == '.') && (p[1] == '\0')) ||
                 ((p[0] == '.') && (p[1] == '.') && (p[2] == '\0')))) {
      return ERR_BAD_ARGS;
    }
    strncpy(info->name, p, NAME_MAX);
    info->name[NAME_MAX] = '\0';

    info->size = (uint64_t)fio->size;
    info->reserved = 0;
  } else {
    info->name[0] = '\0';
    info->size = 0;
    info->reserved = 0;
  }

  return ERR_SUCCESS;
}

/*
// @param[in] fio An open fio. See `zt_fio_open()`.
// @param[out] buf A pointer to a pointer to the buffer with the data read.
// @param[out] bufsize The number of readable bytes placed in @p *buf.
// @return An `err_t` status code.\n\n
// Reads a portion of the underlying file using a sliding window fashion.
// This function provides sequential read access to a file by `mmap()`ing fixed
// size page-aligned chunks into the address space of this process. Each call to
// `zt_fio_read()` advances the read window, `munmap()`ing the previous region
// and `mmap()`ing the next one.\n\n
// The size of the readable data is placed in @p *bufsize. If this function
// is called after the file EOF is reached, @p *bufsize is set to 0 and
// `ERR_EOF` is returned.\n\n
// `zt_fio_close()` will perform the required `munmap()` on the final chunk.
err_t zt_fio_read(zt_fio_t *fio, void **buf, size_t *bufsize) {
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

  if (fio->offset >= fio->size) {
    *buf = NULL;
    *bufsize = 0;
    return ERR_EOF;
  }

  fd = fio->fd;
  flags = fio->flags;
  size = fio->size;
  offset = fio->offset;
  pa_size = MIN(fio->_pa_chunk_size, PA_SIZE(size - offset));

  maddr = mmap(NULL, pa_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, offset);
  if (maddr == MAP_FAILED) {
    log_error(NULL, "Failed to mmap file '%s' (%s)", fio->name, strerror(errno));
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
*/

/**
 * @param[in] fio An open fio. See `zt_fio_open()`.
 * @param[out] buf A pointer to a buffer to read into.
 * @param[in] bufsize The size of the buffer to read into.
 * @param[out] nread The number of bytes read.
 * @return An `err_t` status code.
 *
 * Reads at most @p bufsize bytes of data from the file represented by @p fio
 * into @p buf.
 *
 * If the file EOF is reached, @p nread is set to 0 and `ERR_EOF` is returned.
 */
err_t zt_fio_read(zt_fio_t *fio, void *buf, size_t bufsize, size_t *nread) {
  ssize_t rc;

  if (unlikely(!fio || !buf || !nread))
    return ERR_NULL_PTR;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_READ)))
    return ERR_INVALID;

#if defined(HAVE_POSIX_FADVISE)
  (void)posix_fadvise(fio->fd, fio->offset, bufsize, POSIX_FADV_SEQUENTIAL);
#endif

  *nread = 0;
  rc = read(fio->fd, buf, bufsize);
  switch (rc) {
  case -1:
    log_error(NULL, "Failed to read from file '%s' (%s)", fio->path, strerror(errno));
    return ERR_FIO_READ;
  case 0:
    return ERR_EOF;
  default:
    *nread = rc;
    break;
  }
  fio->offset += rc;

  return ERR_SUCCESS;
}

/**
 * @param[in] fio An open fio. See `zt_fio_open()`.
 * @param[in] total_size The total size of the file to write.
 * @return An `err_t` status code.
 *
 * Prepares the file for writing by allocating space for it using
 * `posix_fallocate(2)`. This is useful for ensuring that the file
 * has enough space allocated before writing to it.
 *
 * Note: Only use this function if the file size is known a priori.
 */
err_t zt_fio_write_allocate(zt_fio_t *fio, off_t total_size) {
  int rv;

  if (!fio)
    return ERR_NULL_PTR;

  if (!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_WRITE))
    return ERR_INVALID;

  if (total_size <= 0)
    return ERR_BAD_ARGS;

  if (fio->fd < 3)
    return ERR_SUCCESS;

#if defined(HAVE_POSIX_FALLOCATE)
  if ((rv = posix_fallocate(fio->fd, 0, total_size)) != 0) {
    switch (rv) {
    case EOPNOTSUPP:
      /** This can be returned in one of two scenarios:
       *  - the underlying libc does not support this operation
       *  - the underlying filesystem does not support the fallocate(2) syscall
       *
       * Return success and try to write the file anyway
       */
      return ERR_SUCCESS;
    default:
      return ERR_FIO_WRITE;
    }
  }
#endif

  return ERR_SUCCESS;
}

/**
 * @param[in] fio An open fio. See `zt_fio_open()`.
 * @param[in] buf A pointer to the buffer with data to write.
 * @param[in] bufsize The number of bytes to write.
 * @return An `err_t` status code.
 *
 * Writes @p bufsize bytes from @p buf to the file represented by @p fio.
 * Partial writes are treated as errors.
 */
err_t zt_fio_write(zt_fio_t *fio, const void *buf, size_t bufsize) {
  ssize_t rc;

  if (unlikely(!fio || !buf))
    return ERR_NULL_PTR;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_WRITE)))
    return ERR_INVALID;

  rc = write(fio->fd, buf, bufsize);
  if (unlikely(rc != bufsize)) {
    log_error(NULL, "Failed to write to file '%s' (%s)", fio->path, strerror(errno));
    return ERR_FIO_WRITE;
  }

  fio->offset += rc;
  return ERR_SUCCESS;
}

/**
 * @param[in] fio An fio opened in one of the writeable modes.
 * @param[out] size Set to the current size of the file after trimming.
 * @return An `err_t` status code.
 *
 * Trims the file represented by @p fio to the current offset.
 *
 * @note For a file whose allocated size was greater than the sum of all
 *       writes through this @p fio, this function will trim the file to
 *       the current offset from the writes.
 */
err_t zt_fio_trim(zt_fio_t *fio, off_t *size) {
  if (unlikely(!fio))
    return ERR_NULL_PTR;

  if (!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_WRITE))
    return ERR_INVALID;

  if (fio->fd < 3)
    return ERR_INVALID;

  if (ftruncate(fio->fd, fio->offset) != 0) {
    log_error(NULL, "Failed to truncate file '%s' (%s)", fio->path, strerror(errno));
    return ERR_INVALID;
  }

  if (size)
    *size = fio->offset;

  return ERR_SUCCESS;
}
