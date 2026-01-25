#ifndef __IO_ASYNC_H__
#define __IO_ASYNC_H__

#include "common/defines.h"
#include "common/time_utils.h"
#include "conn_defs.h"
#include "lib/iomem.h"
#include "lib/vcry.h"

#if defined(_WIN32)
#include <STDLIB.h>
#ifndef _MAX_FNAME
#define _MAX_FNAME 256
#endif
#else
#include <limits.h>
#ifndef NAME_MAX
#define NAME_MAX 255
#endif
#endif

#include <uv.h>

// clang-format off

typedef enum {
  FIO_RDONLY = 1, /* read only */
  FIO_RDWR,       /* read and write */
  FIO_WRONLY,     /* write only */
  FIO_APPEND,     /* append only */
  FIO_RDAPPEND,   /* read and append */
} zt_fio_mode_t;

#define FIO_FL_OPEN       (1U << 0) /* open file */
#define FIO_FL_WRITE      (1U << 1) /* writable file */
#define FIO_FL_READ       (1U << 2) /* readable file */
#define FIO_FL_XL         (1U << 3) /* files of size >= 512MB */
#define FIO_FL_XXL        (1U << 4) /* files of size >= 4GB  */
#define FIO_FL_STREAM     (1U << 5) /* standard stream io */

typedef struct _zt_fio_st {
  void
    *handle,          /* uv fs_request/stream */
    *cbdata;          /* user callback data */
  uv_fs_t
    *req;             /* uv fs read/write request */
  vcry_crypto_hdr_t
    *vcry_hdr;        /* VCRY crypto header */
  ssize_t
    offset;           /* current r/w offset */
  const char
    *path;            /* full system-specific file path */
  zt_fio_cb_t
    *cb;              /* user callback */
  int
    flags;            /* operation flags (FIO_FL_*) */
} zt_fio_t;

typedef struct _zt_fileinfo_st {
  /* NUL-terminated file name */
#if defined(_WIN32)
  char name[_MAX_FNAME + 1];
#else
  char name[NAME_MAX + 1];
#endif
  uint64_t size;  /* Physical file size in bytes */
  uint32_t flags; /* Reserved*/
} zt_fileinfo_t;

// clang-format on

typedef struct _zt_multio_st zt_multio_t;

typedef void(zt_fio_cb_t)(zt_multio_t *, zt_fio_t *, void *);

typedef void(zt_fio_err_cb_t)(zt_multio_t *, zt_fio_t *, err_t, void *);

#endif /* __IO_ASYNC_H__ */