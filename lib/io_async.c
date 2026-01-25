#include "io_async.h"
#include "common/defines.h"
#include "common/log.h"
#include "common/mpmcq.h"

// #include "uv_helper.h" // XXX

#if defined(_WIN32)
#include <stdlib.h> // _splitpath_s
#include <windows.h>
#elif defined(__linux__)
#include <linux/fs.h>
#include <stdatomic.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#error "unsupported platform"
#endif

#if !defined(HAVE_POSIX_FALLOCATE) && defined(__linux__)
#define _GNU_SOURCE // fallocate(2)
#if HAVE_FCNTL
#define HAVE_FALLOCATE 1
#endif
#endif

#if HAVE_FCNTL
#include <fcntl.h>
#endif

/** How far past the page boundary is `offs` */
#define PA_OVERSHOOT(offs) ((offs) & (sysconf(_SC_PAGE_SIZE) - 1))

/** Rounded-up page-aligned size */
#define PA_SIZE(size) ((((size) - 1) | (sysconf(_SC_PAGE_SIZE) - 1)) + 1)

#define FIO_FL_TST(fio, flgs) ((fio->flags & (flgs)) == (flgs))
#define FIO_FL_SET(fio, flag) (fio->flags |= (flag))
#define FIO_FL_CLR(fio, flag) (fio->flags &= ~(flag))

#define _MULTIO_Q_SRC 0x0 /* source queue index */
#define _MULTIO_Q_SNK 0x1 /* sink queue index */

/** Multio object used to register multiple async fio requests */
struct _zt_multio_st {
  uv_loop_t *loop;
  iomem_pool_t *pool;
  mpmc_queue_t *q[2];
#if defined(__linux__)
  atomic_bool active;
#else
#error "not implemented"
#endif
  zt_fio_err_cb_t *err_cb; /* user error callback */
  void *err_cbdata;        /* user error callback data */
  bool init : 1;           /* multio initialized */
};

struct uv__fio_rw_cb_arg {
  zt_fio_t *fio;        /* fio handle */
  zt_multio_t *multio;  /* multio handle */
  iomem_chunk_t *chunk; /* iomem chunk */
};

/** Lock the entire file associated with @p handle */
static int _lock_file(void *handle) {
  uv_fs_t *fs_req = (uv_fs_t *)handle;

#if defined(_WIN32)
  OVERLAPPED sOverlapped;
  sOverlapped.Offset = 0;
  sOverlapped.OffsetHigh = 0;
  HANDLE hFile = (HANDLE)uv_get_osfhandle(fs_req->result);
  // XXX: we want to lock the entire file; locking beyond the file EOF is allowed
  BOOL bSuccess = LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                             0, MAXDWORD, MAXDWORD, &sOverlapped);
  if (!bSuccess)
    return -1;
#elif defined(HAVE_FCNTL)
  struct flock fl;
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0; /* entire file */
  if (fcntl(fs_req->result, F_SETLK, &fl) < 0)
    return -1;
#else
  return -1;
#endif
  return 0;
}

/** Unlock the file associated with @p handle */
static void _unlock_file(void *handle) {
  uv_fs_t *fs_req = (uv_fs_t *)handle;

#if defined(_WIN32)
  OVERLAPPED sOverlapped;
  sOverlapped.Offset = 0;
  sOverlapped.OffsetHigh = 0;
  HANDLE hFile = (HANDLE)uv_get_osfhandle(fs_req->result);
  (void)UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &sOverlapped);
#elif defined(HAVE_FCNTL)
  struct flock fl;
  fl.l_type = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0; /* entire file */
  (void)fcntl(fs_req->result, F_SETLK, &fl);
#endif
}

/** Open a uv tty/pipe handle associated with a standard stream (stdin, stdout) */
static int _open_std_stream(int fd, uv_loop_t *loop, void **handle) {
  ASSERT(fd == 0 || fd == 1); // sanity check

  if (uv_guess_handle(fd) == UV_TTY) {
    uv_tty_t *tty = zt_malloc(sizeof(uv_tty_t));
    if (!tty)
      return -1;
    uv_tty_init(loop, tty, fd, 0);
    *handle = tty;
    return 0;
  } else if (uv_guess_handle(fd) == UV_NAMED_PIPE) {
    uv_pipe_t *pipe = zt_malloc(sizeof(uv_pipe_t));
    if (!pipe)
      return -1;
    uv_pipe_init(loop, pipe, 0);
    uv_pipe_open(pipe, fd);
    *handle = pipe;
    return 0;
  }
  return -1;
}

/**
 * Close the uv handles and free any resources allocated for @p fio
 *
 * This takes care of both standard streams and regular files.
 */
static inline void ATTRIBUTE_NONNULL(1) _reset_fio(zt_fio_t *fio) {
  ASSERT(fio);

  if (fio->handle) {
    if (FIO_FL_TST(fio, FIO_FL_STREAM)) {
      uv_stream_t *stream = (uv_stream_t *)fio->handle;
      uv_close((uv_handle_t *)stream, NULL);
    } else {
      uv_fs_t *fs_req = (uv_fs_t *)fio->handle;

      if (FIO_FL_TST(fio, FIO_FL_OPEN))
        _unlock_file(fio->handle);

      uv_fs_req_cleanup(fs_req);
      uv_fs_close(NULL, fs_req, fs_req->result, NULL); // sync
    }

    zt_free(fio->handle);
    fio->handle = NULL;
  }

  if (fio->req) {
    if (fio->req->data)
      zt_free(fio->req->data);

    uv_fs_req_cleanup(fio->req); // no harm in cleaning up twice
    zt_free(fio->req);
  }

  zt_free(fio->path);

  memset(fio, 0, sizeof(zt_fio_t));
}

/**
 * @param[in] multio An initalized multio handle.
 * @param[in] fio The fio object to be initialized.
 * @param[in] filepath Complete system-specific filepath.
 * @param[in] mode The file open mode.
 * @param[in] hdr VCRY crypto stream header.
 * @return An `err_t` status code.
 *
 * Open a new fio stream associated with @p filepath in the given @p mode.
 *
 * This function needs to acquire an exclusive lock on the file if @p mode
 * is writeable (i.e., FIO_RDWR, FIO_WRONLY, FIO_APPEND, FIO_RDAPPEND).
 * If the file is opened in read-only mode (FIO_RDONLY), a shared lock is
 * acquired instead.
 *
 * If @p mode is readable, then @p multio must have a sink queue.
 * Similarly, if @p mode is writeable, then @p multio must have a source queue.
 * See `zt_multio_init()`.
 *
 * A read operation requests chunks from the multio's mempool, reads data
 * from the file into the chunk, and then enqueues the chunk onto the multio's
 * sink queue. These chunks must be returned to the mempool by the application.
 *
 * A write operation dequeues chunks from the multio's source queue and
 * writes the chunk data to the file. The chunks are returned to the mempool
 * after the write is complete.
 *
 * The caller must call `zt_fio_close()` on this @p fio after all operations
 * are complete.
 */
err_t zt_fio_open(zt_multio_t *multio, zt_fio_t *fio, const char *filepath,
                  zt_fio_mode_t mode, vcry_crypto_hdr_t *hdr) {
  err_t ret;
  int fd = -1, flags = 0, rv;
  struct flock fl;

  if (!fio || !multio || !filepath || !hdr)
    return ERR_NULL_PTR;

  if (!multio->init)
    return ERR_BAD_ARGS;

  _reset_fio(fio);

  /* if (!strcmp(filepath, "-")) {
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
    if (_open_std_stream(fd, multio->loop, &fio->handle) < 0) {
      log_error(NULL, "Could not open standard stream -- not a TTY or pipe");
      return ERR_INTERNAL;
    }
    FIO_FL_SET(fio, FIO_FL_STREAM | FIO_FL_OPEN | flags);
    return ERR_SUCCESS;
  } */

  fio->handle = zt_malloc(sizeof(uv_fs_t));
  fio->req = zt_malloc(sizeof(uv_fs_t));

  if (!fio->handle || !fio->req) {
    ret = ERR_MEM_FAIL;
    goto cleanup;
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
    rv = uv_fs_open(multio->loop, fio->handle, filepath, flags, 0, NULL);
  else
    rv = uv_fs_open(multio->loop, fio->handle, filepath, flags | O_CREAT, 0600, NULL);

  if (rv < 0) {
    log_error(NULL, "Failed to open file '%s' (%s)", filepath, uv_strerror(rv));
    ret = ERR_BAD_ARGS;
    goto cleanup;
  }

  if (_lock_file(fio->handle) < 0) {
    log_error(NULL, "Failed to lock file '%s' (%s)", filepath, strerror(errno));
    ret = ERR_INTERNAL;
    goto cleanup;
  }

  fio->path = zt_strdup(filepath);
  fio->vcry_hdr = hdr;

  FIO_FL_SET(fio, FIO_FL_OPEN);

  /** Set the operation access flags */
  if (mode == FIO_RDONLY)
    FIO_FL_SET(fio, FIO_FL_READ);
  else if (mode == FIO_WRONLY)
    FIO_FL_SET(fio, FIO_FL_WRITE);
  else
    FIO_FL_SET(fio, FIO_FL_READ | FIO_FL_WRITE);

  return ERR_SUCCESS;

cleanup:
  _reset_fio(fio);
  return ret;
}

/**
 * @param[in] fio The fio handle to close.
 * @return Void.
 *
 * Closes the fio and frees any associated resources.
 *
 * WARNING: Closing an fio with an ongoing/pending asynchronous operation
 * will lead to undefined behavior. To make sure the @p fio is safe to close,
 * use `zt_fio_waitfor_idle()`.
 */
void zt_fio_close(zt_fio_t *fio) {
  if (fio)
    _reset_fio(fio);
}

/**
 * @param[in] multio An uninitialized multio handle.
 * @param[in] loop The uv loop to use for async fio operations.
 * @param[in] pool An iomem pool to use for fio operations.
 * @param[in] src_q A source mpmc queue for write operations. May be NULL.
 * @param[in] sink_q A sink mpmc queue for read operations. May be NULL.
 * @return An `err_t` status code.
 *
 * Initialize a multio handle to concurrently perform multiple asynchronous
 * fio operations.
 *
 * If write operations are to be performed using this @p multio,
 * then @p src_q must be a valid mpmc queue from which chunks
 * to write are dequeued.
 * Similarly, if read operations are to be performed,
 * then @p sink_q must be a valid mpmc queue onto which read
 * chunks are enqueued.
 */
err_t zt_multio_init(zt_multio_t *multio, uv_loop_t *loop, iomem_pool_t *pool,
                     mpmc_queue_t *src_q, mpmc_queue_t *sink_q) {
  if (!multio || !loop || !pool)
    return ERR_NULL_PTR;

  memset(multio, 0, sizeof(zt_multio_t));

  multio->loop = loop;
  multio->pool = pool;
  multio->q[_MULTIO_Q_SRC] = src_q;
  multio->q[_MULTIO_Q_SNK] = sink_q;
  atomic_store_explicit(&multio->active, false, memory_order_release);
  multio->init = true;

  return ERR_SUCCESS;
}

/**
 * @param[in] multio An initalized multio handle.
 *
 * Start the multio event loop.
 * This function will terminate all operations registered to this @p multio.
 */
void zt_multio_stop(zt_multio_t *multio) {
  if (!atomic_load_explicit(&multio->active, memory_order_acquire))
    return;

  atomic_store_explicit(&multio->active, false, memory_order_release);
  uv_stop(multio->loop);
}

/**
 * @param[in] multio An initalized multio handle.
 * @param[in] cb User error callback.
 * @param[in] cbdata User callback data.
 *
 * Set the error callback for the multio object. This callback is invoked
 * as `cb(multio, fio, errcode, cbdata)` whenever an asynchronous
 * fio operation fails. The application logic is free to decide what happens to all fios
 * registered to this @p multio whenever an active fio operation fails.
 *
 * WARNING: Without an error callback set, fio operations associated with this @p multio
 * handle will fail silently.
 */
void zt_multio_set_err_cb(zt_multio_t *multio, zt_fio_err_cb_t *cb, void *cbdata) {
  if (!multio || !multio->init)
    return;

  multio->err_cb = cb;
  multio->err_cbdata = cbdata;
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
 * Get the physical size of the file represented by an open fio handle
 * @note This should not be a handle to a stream */
static inline uint64_t ATTRIBUTE_NONNULL(1) zt_file_getsize(uv_fs_t *handle) {
#if defined(_WIN32)
  HANDLE h = (HANDLE)uv_get_osfhandle(handle->result);
  LARGE_INTEGER size;
  if (likely(h != INVALID_HANDLE_VALUE)) {
    if (likely(GetFileSizeEx(h, &size)))
      return (uint64_t)size.QuadPart;
  }
#else
  int fd = handle->result;
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
#endif
  return UINT64_MAX;
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
  uint64_t size;

  if (unlikely(!fio || !info))
    return ERR_NULL_PTR;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN)))
    return ERR_BAD_ARGS;

  if (!FIO_FL_TST(fio, FIO_FL_STREAM)) {
#if defined(_WIN32)
    if (_splitpath_s(fio->path, NULL, 0, NULL, 0, (wchar_t *)info->name, _MAX_FNAME, NULL,
                     0) != 0) {
      return ERR_BAD_ARGS;
    }
    info->name[_MAX_FNAME] = '\0';
#else
    p = basename(fio->path);
    /** Sanity check; this should never happen with an open fio */
    if (unlikely((p[0] == '/') || ((p[0] == '.') && (p[1] == '\0')) ||
                 ((p[0] == '.') && (p[1] == '.') && (p[2] == '\0')))) {
      return ERR_BAD_ARGS;
    }
    strncpy(info->name, p, NAME_MAX);
    info->name[NAME_MAX] = '\0';
#endif

    if ((size = _get_filesize(fio->handle)) == UINT64_MAX)
      return ERR_BAD_ARGS;
    info->size = size;

    info->flags = 0;
  } else {
    info->name[0] = '\0';
    info->size = 0;
    info->flags = 0;
  }

  return ERR_SUCCESS;
}

static inline int ATTRIBUTE_NONNULL(1) _alloc_file(uv_fs_t *handle, size_t total_size) {
#if defined(_WIN32)
  HANDLE hFile;
  LARGE_INTEGER size;

  hFile = (HANDLE)uv_get_osfhandle(handle->result);
  if (hFile == INVALID_HANDLE_VALUE)
    return -1;

  size.QuadPart = (LONGLONG)total_size;
  if (!SetEndOfFileEx(hFile, 0, size, FILE_BEGIN))
    goto err;

  /**
   * Set the physical size (end of file) to the offset `FILE_BEGIN+total_size`.
   * This should give us the early failure we want if the disk doesn't have enough space.
   * XXX: This hasn't been tested
   */
  if (!SetEndOfFile(hFile))
    goto err;

  return 0;
err:
  log_error(NULL, "Failed to allocate %zu bytes for file (0x%X)", total_size,
            GetLastError());
  return -1;
#elif defined(HAVE_POSIX_FALLOCATE) || defined(HAVE_FALLOCATE)
  int rv, fd;

  fd = handle->result;
  if (fd < 3)
    return -1;

#ifdef HAVE_POSIX_FALLOCATE
  if ((rv = posix_fallocate(fd, 0, total_size)) != 0)
#else
  if ((rv = fallocate(fd, 0, 0, total_size)) != 0)
#endif
  {
    switch (rv) {
    case EOPNOTSUPP:
      /** This can be returned in one of two scenarios:
       *  - the underlying libc does not support this operation
       *  - the underlying filesystem does not support the fallocate(2) syscall
       *
       * Return success and try to write the file anyway
       */
      return -1;
    default:
      log_error(NULL, "Failed to allocate %zu bytes for file (%s)", total_size,
                strerror(rv));
      return -1;
    }
  }
  return 0;
#endif
}

/**
 * @param[in] fio An open fio. See `zt_fio_open()`.
 * @param[in] total_size The total size of the file to write.
 * @return An `err_t` status code.
 *
 * On Windows:
 *  Sets the physical file size (end of file) using `SetEndOfFile()`.
 * On POSIX systems:
 *  Prepares the file for writing by allocating space for it using
 *  `posix_fallocate(2)`. This is useful for ensuring that the file
 *  has enough space allocated before writing to it.
 *
 * NOTE: The @p fio must not be associated with a stdio stream.
 */
err_t zt_fio_write_allocate(zt_fio_t *fio, off_t total_size) {
  uv_fs_t *handle;

  if (!fio)
    return ERR_NULL_PTR;

  if (!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_WRITE) || FIO_FL_TST(fio, FIO_FL_STREAM))
    return ERR_INVALID;

  if (total_size <= 0)
    return ERR_BAD_ARGS;

  handle = (uv_fs_t *)fio->handle;

  if (_alloc_file(handle, total_size) < 0)
    return ERR_INVALID;
  else
    return ERR_SUCCESS;
}

struct uv__fio_rw_cb_arg {
  zt_fio_t *fio;        /* fio handle */
  zt_multio_t *multio;  /* multio handle */
  iomem_chunk_t *chunk; /* iomem chunk */
};

/** */
static void uv__fio_read_cb(uv_fs_t *req) {
  int rv;
  ssize_t result;
  struct uv__fio_rw_cb_arg *a = req->data;

  if (unlikely(!atomic_load_explicit(&a->multio->active, memory_order_acquire)))
    return;

  result = req->result;
  uv_fs_req_cleanup(req);

  if (result > 0) {
    // forward chunk to processing queue
    // XXX: this can block indefinitely
    // possible fix: a control thread that detects blocked threads?
    rv = mpmc_queue_enqueue(a->multio->q[_MULTIO_Q_SNK], a->chunk, MPMC_Q_NONE);
    ASSERT(rv == 0);

    // schedule next read
    a->fio->offset += result;
    _fio_read_chunk(a->multio, a->fio);
  } else if (result == 0) {
    // reached EOF

    iomem_pool_free_chunk(a->multio->pool, a->chunk); // throw away chunk

    if (a->fio->cb)
      a->fio->cb(a->multio, a->fio, a->fio->cbdata);
  } else {
    log_error("Failed to read from file (stream=%p, offset=%zu) (%s)",
              PTR64(a->fio->vcry_hdr->sid), a->fio->offset, uv_strerror((int)result));

    iomem_pool_free_chunk(a->multio->pool, a->chunk); // throw away chunk

    if (a->multio->err_cb)
      a->multio->err_cb(a->multio, a->fio, ERR_FIO_READ, a->multio->err_cbdata);
  }
}

/**  */
static void _fio_read_chunk(zt_multio_t *multio, zt_fio_t *fio) {
  int rv;
  uv_file file;
  uv_buf_t buf;
  uv_req_t *fs_req;
  iomem_chunk_t *chunk;

  if (unlikely(!atomic_load_explicit(&multio->active, memory_order_acquire)))
    return;

  chunk = iomem_pool_get_chunk(multio->pool);
  ASSERT(chunk);
  ((struct uv__fio_rw_cb_arg *)fs_req->data)->chunk = chunk;

  buf = uv_buf_init(chunk->mem, chunk->size - ZT_MSG_HEADER_SIZE);

  file = ((uv_fs_t *)fio->handle)->result;

  fs_req = fio->req;

  rv = uv_fs_read(multio->loop, fio->req, file, &buf, 1, fio->offset, uv__fio_read_cb);
  if (rv < 0) {
    log_error(NULL, "Failed to read from file (stream=%p, offset=%zu) (%s)",
              PTR64(fio->vcry_hdr->sid), fio->offset, uv_strerror(rv));
    iomem_pool_free_chunk(multio->pool, chunk);

    if (multio->err_cb)
      multio->err_cb(multio, fio, ERR_FIO_READ, multio->err_cbdata);
  }
}

/** */
err_t zt_fio_readstream_start(zt_multio_t *multio, zt_fio_t *fio, zt_fio_cb_t cb,
                              void *cbdata) {
  struct uv__fio_rw_cb_arg *arg;

  if (unlikely(!multio || !fio))
    return ERR_NULL_PTR;

  // not yet supported
  if (unlikely(FIO_FL_TST(fio, FIO_FL_STREAM)))
    return ERR_NOT_SUPPORTED;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_READ)))
    return ERR_INVALID;

  if (unlikely(!multio->init))
    return ERR_BAD_ARGS;

  if (iomem_pool_chunk_size(multio->pool) <= ZT_MSG_HEADER_SIZE)
    return ERR_BUFFER_TOO_SMALL;

  if (!(arg = zt_calloc(1, sizeof(struct uv__fio_rw_cb_arg))))
    return ERR_MEM_FAIL;

  /* set fio, multio handles for uv read callbacks */
  arg->fio = fio;
  arg->multio = multio;
  fio->req->data = PTRV(arg);

  fio->cb = cb;
  fio->cbdata = cbdata;

  // fire callback chain
  _fio_read_chunk(multio, fio);

  return ERR_SUCCESS;
}

static void uv__fio_write_cb(uv_fs_t *req) {
  int rv;
  ssize_t result;
  struct uv__fio_rw_cb_arg *a = req->data;

  if (unlikely(!atomic_load_explicit(&a->multio->active, memory_order_acquire)))
    return;

  result = req->result;
  uv_fs_req_cleanup(req);

  // the chunk must be returned to the pool regardless of the result
  iomem_pool_free_chunk(a->multio->pool, a->chunk);

  if (result >= 0) {
    a->fio->offset += result;

    // schedule next write
    _fio_write_chunk(a->multio, a->fio);
  } else {
    log_error("Failed to write to file (stream=%p, offset=%zu) (%s)",
              PTR64(a->fio->vcry_hdr->sid), a->fio->offset, uv_strerror((int)result));

    if (a->multio->err_cb)
      a->multio->err_cb(a->multio, a->fio, ERR_FIO_WRITE, a->multio->err_cbdata);
  }
}

/** */
static void _fio_write_chunk(zt_multio_t *multio, zt_fio_t *fio) {
  int rv;
  uv_file file;
  uv_buf_t buf;
  uv_req_t *fs_req;
  iomem_chunk_t *chunk;

  if (unlikely(!atomic_load_explicit(&multio->active, memory_order_acquire)))
    return;

  // XXX: this can block indefinitely
  rv = mpmc_queue_dequeue(multio->q[_MULTIO_Q_SRC], (void **)&chunk, MPMC_Q_NONE);
  ASSERT(rv == 0);
  ((struct uv__fio_rw_cb_arg *)fs_req->data)->chunk = chunk;

  buf = uv_buf_init(chunk->mem, chunk->size);

  file = ((uv_fs_t *)fio->handle)->result;

  fs_req = fio->req;

  rv = uv_fs_write(multio->loop, fio->req, file, &buf, 1, fio->offset, uv__fio_write_cb);
  if (rv < 0) {
    log_error(NULL, "Failed to write to file (stream=%p, offset=%zu) (%s)",
              PTR64(fio->vcry_hdr->sid), fio->offset, uv_strerror(rv));

    iomem_pool_free_chunk(multio->pool, chunk);

    if (multio->err_cb)
      multio->err_cb(multio, fio, ERR_FIO_WRITE, multio->err_cbdata);
  }
}

err_t zt_fio_writestream_start(zt_multio_t *multio, zt_fio_t *fio, zt_fio_cb_t cb,
                               void *cbdata) {
  struct uv__fio_rw_cb_arg *arg;

  if (unlikely(!multio || !fio))
    return ERR_NULL_PTR;

  // not yet supported
  if (unlikely(FIO_FL_TST(fio, FIO_FL_STREAM)))
    return ERR_NOT_SUPPORTED;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_WRITE)))
    return ERR_INVALID;

  if (unlikely(!multio->init))
    return ERR_BAD_ARGS;

  if (!(arg = zt_calloc(1, sizeof(struct uv__fio_rw_cb_arg))))
    return ERR_MEM_FAIL;

  /* set fio, multio handles for uv write callbacks */
  arg->fio = fio;
  arg->multio = multio;
  fio->req->data = PTRV(arg);

  fio->cb = cb;
  fio->cbdata = cbdata;

  // fire callback chain
  _fio_write_chunk(multio, fio);

  return ERR_SUCCESS;
}

/**
 * @param[in] fio An fio opened in one of the writeable modes.
 * @param[out] size Set to the current size of the file after trimming.
 * @return An `err_t` status code.
 *
 * Trims the file represented by @p fio to the current offset.
 *
 * For a file whose allocated size was greater than the sum of all
 * writes through this @p fio, this function will trim the file to
 * the current offset from the writes.
 *
 * NOTE: The @p fio must not be associated with an stdio stream.
 */
err_t zt_fio_trim(zt_fio_t *fio, off_t *size) {
  uv_fs_t *handle;
#if defined(_WIN32)
  HANDLE h;
  LARGE_INTEGER offs;
#else
  int fd;
#endif

  if (unlikely(!fio))
    return ERR_NULL_PTR;

  if (unlikely(!FIO_FL_TST(fio, FIO_FL_OPEN | FIO_FL_WRITE) ||
               FIO_FL_TST(fio, FIO_FL_STREAM)))
    return ERR_BAD_ARGS;

  handle = (uv_fs_t *)fio->handle;

#if defined(_WIN32)
  h = (HANDLE)uv_get_osfhandle(handle->result);
  offs.QuadPart = fio->offset;

  if (h == INVALID_HANDLE_VALUE)
    return ERR_INVALID;

  if (!SetFilePointerEx(h, offs, NULL, FILE_BEGIN)) {
    log_error(NULL, "Failed to set file pointer for '%s' (0x%X)", fio->path,
              GetLastError());
    return ERR_INVALID;
  }

  if (!SetEndOfFile(h)) {
    log_error(NULL, "Failed to set EOF for '%s' (0x%X)", fio->path, GetLastError());
    return ERR_INVALID;
  }
#else
  fd = handle->result;
  if (fd < 3)
    return ERR_INVALID;

  if (ftruncate(fd, fio->offset) != 0) {
    log_error(NULL, "Failed to truncate file '%s' (%s)", fio->path, strerror(errno));
    return ERR_INVALID;
  }
#endif

  if (size)
    *size = fio->offset;

  return ERR_SUCCESS;
}
