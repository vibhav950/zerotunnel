#include "io.h"
#include "ztlib.h"

#include <errno.h>
#include <error.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

// /**
//  * @param[in] sockfd The socket file descriptor to wait for.
//  * @param[in] timeout_msec The wait timeout in milliseconds.
//  * @param[in] mode `ZT_NETIO_READABLE`, `ZT_NETIO_WRITABLE`, or the bitwise
//  OR
//  * of the two.
//  * @return -1 on error or timeout, otherwise check for the bitwise OR of
//  * `ZT_NETIO_READABLE` and `ZT_NETIO_WRITABLE`.
//  *
//  * Wait for the socket to become readable/writable.
//  *
//  * Following values of @p timeout_msec are special:
//  * If `0`, the function will return immediately.
//  * If `-1`, the function will wait indefinitely.
//  */
// int zt_tcp_io_waitfor(int sockfd, timediff_t timeout_msec, int mode) {
//   int rc;
//   int flags, error;
//   fd_set rset, wset;
//   fd_set *rsetp, *wsetp;
//   struct timeval tval;
//   socklen_t len;

//   FD_ZERO(&rset);
//   FD_SET(sockfd, &rset);
//   wset = rset;

//   /**
//    * Prepare fd set arguments depending upon whether we are watching for
//    * readability, writability, or both
//    */
//   rsetp = (mode & ZT_NETIO_READABLE) ? &rset : NULL;
//   wsetp = (mode & ZT_NETIO_WRITABLE) ? &wset : NULL;

//   tval.tv_sec = timeout_msec / 1000;
//   tval.tv_usec = (timeout_msec % 1000) * 1000;

//   if (select(sockfd + 1, rsetp, wsetp, NULL,
//              (timeout_msec >= 0) ? &tval : NULL) == 0) {
//     PRINTERROR("Connection timed out\n");
//     return -1;
//   }

//   rc = 0;
//   /** Socket readable? */
//   if (mode & ZT_NETIO_READABLE) {
//     if (!FD_ISSET(sockfd, &rset))
//       rc |= ZT_NETIO_READABLE;
//   }
//   /** Socket writable? */
//   if (mode & ZT_NETIO_WRITABLE) {
//     if (!FD_ISSET(sockfd, &wset))
//       rc |= ZT_NETIO_WRITABLE;
//   }

//   len = sizeof(error);
//   if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
//     PRINTERROR("getsockopt failed (%s)\n", strerror(errno));
//     rc = -1;
//   }
//   /** Check for pending socket error */
//   if (error)
//     rc = -1;

//   return rc;
// }

/**
 * @param[in] sockfd The socket file descriptor to wait for.
 * @param[in] timeout_msec The wait timeout in milliseconds.
 * @param[in] mode `ZT_NETIO_READABLE`, `ZT_NETIO_WRITABLE`, or the bitwise OR
 * of the two.
 * @return -1 on error or timeout, otherwise check for the bitwise OR of
 * `ZT_NETIO_READABLE` and `ZT_NETIO_WRITABLE`.
 *
 * Wait for the socket to become readable/writable.
 *
 * Following values of @p timeout_msec are special:
 * If `0`, the function will return immediately.
 * If `-1`, the function will wait indefinitely.
 */
int zt_tcp_io_waitfor(int sockfd, timediff_t timeout_msec, int mode) {
  return zt_io_waitfor(sockfd, timeout_msec, mode);
}

/**
 * @param[in] sockfd The socket file descriptor to wait for.
 * @param[in] timeout_msec The wait timeout in milliseconds.
 * @return `true` if the socket is readable, `false` otherwise.
 *
 * Wait for the socket to become readable.
 *
 * Following values of @p timeout_msec are special:
 * If `0`, the function will return immediately.
 * If `-1`, the function will wait indefinitely.
 */
bool zt_tcp_io_waitfor_read(int sockfd, timediff_t timeout_msec) {
  // return zt_tcp_io_waitfor(sockfd, timeout_msec, ZT_NETIO_READABLE) > 0;
  return zt_io_waitfor(sockfd, timeout_msec, ZT_IO_READABLE) > 0;
}

/**
 * @param[in] sockfd The socket file descriptor to wait for.
 * @param[in] timeout_msec The wait timeout in milliseconds.
 * @return `true` if the socket is writable, `false` otherwise.
 *
 * Wait for the socket to become writable.
 *
 * Following values of @p timeout_msec are special:
 * If `0`, the function will return immediately.
 * If `-1`, the function will wait indefinitely.
 */
bool zt_tcp_io_waitfor_write(int sockfd, timediff_t timeout_msec) {
  // return zt_tcp_io_waitfor(sockfd, timeout_msec, ZT_NETIO_WRITABLE) > 0;
  return zt_io_waitfor(sockfd, timeout_msec, ZT_IO_WRITABLE) > 0;
}

/**
 * @param[in] conn The client connection context.
 * @param[in] buf The buffer to send.
 * @param[in] nbytes The number of bytes to send.
 * @return 0 if all the bytes were sent, -1 otherwise.
 *
 * Write exactly @p nbytes from @p buf to the TCP connection represented by
 * @p conn.
 *
 * This function will treat a partial write as an error and return -1.
 *
 * TCP Fast Open will be used if it is enabled and available. It can be enabled
 * using `zt_client_set_tcp_fastopen()`.
 *
 * If a timeout has been set, this function will wait for at most
 * @p send_timeout milliseconds in the event of an unwritable socket before
 * retrying once again. If the socket still does not become writable, the
 * function returns zero.
 *
 * The timeout can be set using `zt_client_set_send_timeout()`.
 */
int zt_client_tcp_send(zt_client_connection_t *conn, const uint8_t *buf,
                       size_t nbytes) {
  ssize_t nwritten = 0;

  if (unlikely(!conn || !buf || !nbytes))
    return -1;

  while (nbytes) {
    ssize_t n = send(conn->sockfd, buf, nbytes, 0);

    if (n > 0) {
      nwritten += n;

      if ((size_t)n >= nbytes)
        return 0; // sent exactly nbytes

      nbytes -= n;
      buf += n;
    } else if (conn->send_timeout && (errno == EAGAIN)) {
      if (!zt_tcp_io_waitfor_write(conn->sockfd, conn->send_timeout))
        return -1;
    } else {
      return -1;
    }
  }
}

/**
 * @param[in] conn The client connection context.
 * @param[out] buf The buffer to read into.
 * @param[in] nbytes The length of the buffer.
 * @param[out] pending Set to `true` if there is more data to be read, `false`
 * otherwise.
 * @return Number of bytes read, or -1 on error.
 *
 * Read a maximum of @p nbytes bytes from the TCP connection represented by
 * @p conn into the output buffer @p buf.
 *
 * If there is still data to be read on the socket, the function will set
 * @p pending to `true`. The remaining data can be read by calling the function
 * again.
 *
 * We therefore have the following scenarios (where `n_avail` is the number of
 * bytes available to be read from the socket):
 *
 * 1. `nbytes == n_avail`: The function will read at most `nbytes` bytes,
 * `pending` is set to `false`.
 *
 * 2. `nbytes > n_avail`: The function will read at most `n_avail` bytes,
 * `pending` is set to `false`.
 *
 * 3. `nbytes < n_avail`: The function will read at most `nbytes` bytes,
 * `pending` is set to `true`.
 *
 * Note: It is important to check how many bytes were actually read.
 *
 * If a timeout has been set, this function will wait for at most
 * @p recv_timeout milliseconds till there is data to read on the socket.
 * If the socket does not become "readable" within this time, the function
 * returns the number of bytes read.
 *
 * The timeout can be set using `zt_client_set_recv_timeout()`.
 */
ssize_t zt_client_tcp_recv(zt_client_connection_t *conn, uint8_t *buf,
                           size_t nbytes, bool *pending) {
  ssize_t nread;

  if (unlikely(!conn || !buf || !nbytes))
    return -1;

  nread = 0;
  while ((size_t)nread < nbytes) {
    ssize_t n = recv(conn->sockfd, buf + nread, nbytes - nread, 0);

    if (n == 0) { // server said fuck you
      PRINTERROR("Unexpected socket shutdown by peer");
      return -1;
    }

    if (n > 0) {
      nread += n;
    } else if (conn->recv_timeout && (errno == EAGAIN)) {
      if (!zt_tcp_io_waitfor_read(conn->sockfd, conn->recv_timeout))
        return nread;
    } else {
      return -1;
    }
  }

  // Signal the caller if there is more data to be read
  if (pending) {
    if (zt_tcp_io_waitfor_read(conn->sockfd, 0))
      *pending = true;
    else
      *pending = false;
  }
  return nread;
}
