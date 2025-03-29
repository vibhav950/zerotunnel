#include "defines.h"

#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * @param[in] fd An open file descriptor.
 * @return void.
 *
 * Zero out a file given by @p fd. The file descriptor must be opened before
 * calling this function. The file descriptor is not closed by this function.
 *
 * Note: @p fd must not point to a special file like a socket or a pipe.
 */
void fzero(int fd) {
  int fdz;
  off_t size;
  struct stat st;
  if (fd < 0)
    return;

  if (fstat(fd, &st) == -1)
    return;
  size = st.st_size;

  if ((fdz = open("/dev/zero", O_WRONLY | O_ASYNC)) != -1)
    size -= sendfile(fd, fdz, NULL, size);
  close(fdz);

  if (size) {
    lseek(fd, 0, SEEK_SET);
    write(fd, "\0", size);
  }
}
