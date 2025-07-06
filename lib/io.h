#ifndef __IO_H__
#define __IO_H__

#include "common/defines.h"

#include <limits.h>

// clang-format off

/** File descriptor readable */
#define ZT_IO_READABLE 0x01
/** File descriptor writable */
#define ZT_IO_WRITABLE 0x02

int zt_io_waitfor(int fd, timediff_t timeout_msec, int mode);
bool zt_io_waitfor_read(int fd, timediff_t timeout_msec);
bool zt_io_waitfor_write(int fd, timediff_t timeout_msec);

typedef enum {
  FIO_RDONLY = 1, /* read only */
  FIO_RDWR,       /* read and write */
  FIO_WRONLY,     /* write only */
  FIO_APPEND,     /* append only */
  FIO_RDAPPEND,   /* read and append */
} zt_fio_mode_t;

#define SIZE_KB ((off_t)1024)    /* 1 KB */
#define SIZE_MB (1024 * SIZE_KB) /* 1 MB */
#define SIZE_GB (1024 * SIZE_MB) /* 1 GB */

#define FIO_FL_OPEN     (1U << 0)  /* open file */
#define FIO_FL_WRITE    (1U << 1)  /* writable file */
#define FIO_FL_READ     (1U << 2)  /* readable file */
#define FIO_FL_XL       (1U << 3)  /* files of size >= 512MB */
#define FIO_FL_XXL      (1U << 4)  /* files of size >= 4GB  */

/* ~100KB region for 4KB pages (for files >= 512MB) */
#define FIO_CHUNK_SIZE_XL (24 * sysconf(_SC_PAGE_SIZE))
/* ~200KB region for 4KB pages (for files >= 4GB) */
#define FIO_CHUNK_SIZE_XXL (48 * sysconf(_SC_PAGE_SIZE))

typedef struct _zt_fio_st {
  int fd;
  char *path;
  int flags;
  off_t size;
  off_t offset;
  void *_prev;
  size_t _prevsize;
  size_t _pa_chunk_size;
} zt_fio_t;

typedef struct _zt_fileinfo_st {
  uint8_t name[NAME_MAX + 1];
  uint64_t size;
  uint32_t reserved;
} zt_fileinfo_t;

// clang-format on

err_t zt_file_delete(const char *filepath);

err_t zt_file_zdelete(const char *filepath);

err_t zt_file_rename(const char *oldpath, const char *newpath);

off_t zt_file_getsize(int fd);

err_t zt_fio_open(zt_fio_t *fio, const char *name, zt_fio_mode_t mode);

void zt_fio_close(zt_fio_t *fio);

err_t zt_fio_fileinfo(zt_fio_t *fio, zt_fileinfo_t *info);

// err_t zt_fio_read(zt_fio_t *fio, void **buf, size_t *bufsize);
err_t zt_fio_read(zt_fio_t *fio, void *buf, size_t bufsize, size_t *nread);

err_t zt_fio_write(zt_fio_t *fio, const void *buf, size_t bufsize);

#endif /* __IO_H__ */
