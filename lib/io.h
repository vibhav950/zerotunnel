#ifndef __IO_H__
#define __IO_H__

#include "common/defines.h"

/** File descriptor readable */
#define ZT_IO_READABLE                  0x01
/** File descriptor writable */
#define ZT_IO_WRITABLE                  0x02

int zt_io_waitfor(int fd, timediff_t timeout_msec, int mode);

bool zt_io_waitfor_read(int fd, timediff_t timeout_msec);

bool zt_io_waitfor_write(int fd, timediff_t timeout_msec);

#endif /* __IO_H__ */