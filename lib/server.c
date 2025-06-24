
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "server.h"

#include "vcry.h"
#include "ztlib.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#define accept4(a, b, c, d) accept(a, b, c);
#endif

#define SERVERSTATE_CHANGE(cur, next) (void)(cur = next)

static const char serverstate_names[][20] = {
    [SERVER_NONE] = "SERVER_NONE",
    [SERVER_CONN_INIT] = "SERVER_CONN_INIT",
    [SERVER_AUTH_REPLY] = "SERVER_AUTH_REPLY",
    [SERVER_AUTH_COMPLETE] = "SERVER_AUTH_COMPLETE",
    [SERVER_COMMIT] = "SERVER_COMMIT",
    [SERVER_TRANSFER] = "SERVER_TRANSFER",
    [SERVER_DONE] = "SERVER_DONE"};

static inline const char *get_serverstate_name(ZT_SERVER_STATE state) {
  ASSERT(state >= SERVER_NONE && state <= SERVER_DONE);
  return serverstate_names[state];
}

static inline bool isIPv6(const char *addr) {
  if (!addr)
    return false; /* NULL defaults to 0.0.0.0 */
  char buf[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET6, addr, buf) == 0)
    return false;
  return true;
}

static error_t zt_server_setup_host(zt_server_connection_t *conn,
                                    struct zt_addrinfo **ai_list) {
  error_t ret = ERR_SUCCESS;
  int status;
  struct zt_addrinfo *ai_head = NULL, *ai_tail = NULL, *ai_cur;
  struct addrinfo hints, *res = NULL, *p;
  size_t saddr_len;
  char ipstr[INET6_ADDRSTRLEN];

  ASSERT(conn);
  ASSERT(conn->state == SERVER_CONN_INIT);

  /** check for IPv6 support */
  if (isIPv6(conn->hostname)) {
#ifdef USE_IPV6
    /** check if the system has IPv6 enabled */
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s < 0) {
      PRINTERROR("An IPv6 address was specified, but the system does not "
                 "support or has disabled IPv6 (%s)",
                 strerror(errno));
      return ERR_NOT_SUPPORTED;
    }
#else
    PRINTERROR("An IPv6 address was specified, but zerotunnel was compiled "
               "without `USE_IPV6`");
    return ERR_NOT_SUPPORTED;
#endif
  }

  zt_memset(&hints, 0, sizeof(hints));
  hints.ai_canonname = NULL;
  hints.ai_family = (conn->hostname == NULL) ? AF_INET : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  if ((status = getaddrinfo(conn->hostname ? conn->hostname : "0.0.0.0",
                            conn->port ? conn->port : ZT_DEFAULT_LISTEN_PORT,
                            &hints, &res)) != 0) {
    const char *errstr = (status == EAI_SYSTEM) ? (const char *)strerror(errno)
                                                : gai_strerror(status);

    PRINTERROR("getaddrinfo: error getting local address and port (%s)",
               conn->hostname, errstr);
    return ERR_INTERNAL;
  }

  for (p = res; p != NULL; p = p->ai_next) {
    if (p->ai_family == AF_INET) {
      saddr_len = sizeof(struct sockaddr_in);
    }
#ifdef USE_IPV6
    else if (p->ai_family == AF_INET6) {
      saddr_len = sizeof(struct sockaddr_in6);
    }
#endif
    else {
      continue; /** ignore unsupported address families */
    }

    /** ignore elements without required address info */
    if (!p->ai_addr || !(p->ai_addrlen > 0))
      continue;

    /** ignore elements with bad address length */
    if ((size_t)p->ai_addrlen < saddr_len)
      continue;

    ai_cur =
        (struct zt_addrinfo *)zt_malloc(sizeof(struct zt_addrinfo) + saddr_len);
    if (!ai_cur) {
      ret = ERR_MEM_FAIL;
      goto cleanup;
    }

    /** copy each member */
    ai_cur->ai_flags = p->ai_flags;
    ai_cur->ai_family = p->ai_family;
    ai_cur->ai_socktype = p->ai_socktype;
    ai_cur->ai_protocol = p->ai_protocol;
    ai_cur->ai_addrlen = p->ai_addrlen;
    ai_cur->ai_canonname = NULL;
    ai_cur->ai_addr = NULL;
    ai_cur->ai_next = NULL;

    ai_cur->ai_addr = (void *)((char *)ai_cur + sizeof(struct zt_addrinfo));
    zt_memcpy(ai_cur->ai_addr, p->ai_addr, saddr_len);

    if (!ai_head)
      ai_head = ai_cur;

    if (ai_tail)
      ai_tail->ai_next = ai_cur;
    ai_tail = ai_cur;
  }

  if (!ret)
    *ai_list = ai_head;
  else
    *ai_list = NULL;

cleanup:
  /** if there was an error, free the zt_addrinfo list before exiting */
  if (res)
    zt_addrinfo_free(ai_head);
  freeaddrinfo(res);
  return ret;
}

error_t zt_server_tcp_listen(zt_server_connection_t *conn,
                             struct zt_addrinfo *ai_list) {
  error_t ret = ERR_SUCCESS;
  struct zt_addrinfo *ai_cur, *ai_estab = NULL;
  int sockfd, optval;

  ASSERT(conn);
  ASSERT(conn->state == SERVER_CONN_INIT);
  ASSERT(ai_list);

  for (ai_cur = ai_list; ai_cur; ai_cur = ai_cur->ai_next) {
    (sockfd = socket(ai_cur->ai_family, ai_cur->ai_socktype | SOCK_CLOEXEC,
                     ai_cur->ai_protocol));
    if (sockfd < 0)
      continue; // failed; try next candidate
    if (SOCK_CLOEXEC == 0) {
      /** SOCK_CLOEXEC isn't supported, set O_CLOEXEC using fcntl */
      int flags = fcntl(sockfd, F_GETFD);
      if (flags < 0) {
        PRINTERROR("fcntl: failed to get flags (%s)", strerror(errno));
        flags = 0;
      }
      flags |= FD_CLOEXEC;
      if (fcntl(sockfd, F_SETFD, flags) == -1)
        PRINTERROR("fcntl: failed to set O_CLOEXEC (%s)", strerror(errno));
    }

    optval = 1;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval,
                     sizeof(optval));

    /** Prepare for a live read if required */
    if (conn->fl_live_read) {
      int fail = 0;

      optval = 1;
      if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval,
                     sizeof(optval)) == -1) {
        PRINTERROR("setsockopt: failed to set SO_KEEPALIVE (%s)",
                   strerror(errno));
        fail = 1;
      }

      if (getsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval,
                     sizeof(optval)) == -1) {
        PRINTERROR("getsockopt: failed to get SO_KEEPALIVE (%s)",
                   strerror(errno));
        fail = 1;
      }

      if (fail || !optval) {
        PRINTERROR("could not prepare socket for live read");
        close(sockfd);
        continue;
      }
    }

    if (bind(sockfd, ai_cur->ai_addr, ai_cur->ai_addrlen) == 0)
      break; // success
    else
      PRINTERROR("bind: failed to bind socket (%s)", strerror(errno));

    /** Try to enable TFO */
    if (conn->fl_tcp_fastopen) {
#if defined(TCP_FASTOPEN)
      optval = 5; // allow maximum 5 pending SYNs
      if (setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN, (void *)&optval,
                     sizeof(optval)) == -1) {
        PRINTERROR("setsockopt: failed to set TCP_FASTOPEN (%s)",
                   strerror(errno));
        conn->fl_tcp_fastopen = false;
      }
#else
      PRINTERROR("TCP_FASTOPEN cannot be enabled on this build");
      conn->fl_tcp_fastopen = false;
#endif
    }

    close(sockfd);
  }

  if (!ai_cur) {
    PRINTERROR("could not bind to any suitable local address");
    ret = ERR_BAD_ARGS;
    goto exit;
  }

  ai_estab = zt_malloc(ai_cur->total_size);
  if (!ai_estab) {
    ret = ERR_MEM_FAIL;
    goto exit;
  }
  zt_memcpy(ai_estab, ai_cur, ai_cur->total_size);
  ai_estab->ai_next = NULL;

  conn->ai_estab = ai_estab;
  conn->sockfd = sockfd;

#ifdef DEBUG
  char address[INET6_ADDRSTRLEN + 6];
  getnameinfo(ai_cur->ai_addr, ai_cur->ai_addrlen, address, INET6_ADDRSTRLEN,
              &address[INET6_ADDRSTRLEN], 6, NI_NUMERICHOST | NI_NUMERICSERV);
  PRINTDEBUG("connected to %s:%d", address, &address[INET6_ADDRSTRLEN]);
#endif

  (void)listen(sockfd, 5); // listen with a backlog of 5

exit:
  zt_addrinfo_free(ai_list);
  return ret;
}

error_t zt_server_tcp_accept(zt_server_connection_t *conn) {
  int clientfd, flags;

  ASSERT(conn);
  ASSERT(conn->state == SERVER_CONN_INIT);
  ASSERT(conn->sockfd >= 0);

  clientfd = accept4(conn->sockfd, conn->ai_estab->ai_addr,
                     conn->ai_estab->ai_addrlen, SOCK_CLOEXEC);
  if (clientfd < 0) {
    PRINTERROR("accept4: failed to accept incoming connection (%s)",
               strerror(errno));
    if (errno == ENOSYS) {
      /**
       * On Linux <= 2.6.28 accept4() fails with `ENOSYS`; fallback to accept()
       * Thanks to https://github.com/python/cpython/issues/54324
       */
      PRINTDEBUG("accept4() not supported, falling back to accept()");
      clientfd = accept(conn->sockfd, conn->ai_estab->ai_addr,
                        &conn->ai_estab->ai_addrlen);
      if (clientfd < 0) {
        PRINTERROR("accept: failed to accept incoming connection (%s)",
                   strerror(errno));
        close(conn->sockfd);
        return ERR_TCP_ACCEPT;
      }
    }
  }
  conn->clientfd = clientfd;

  if (conn->send_timeout > 0) {
    struct timeval tval = {.tv_sec = conn->send_timeout / 1000,
                           .tv_usec = (conn->send_timeout % 1000) * 1000};
    if (setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tval,
                   sizeof(tval)) == -1) {
      PRINTERROR("setsockopt: failed to set SO_SNDTIMEO (%s)", strerror(errno));
      close(clientfd);
      return ERR_TCP_ACCEPT; // TODO: better error code?
    }
  }

  if (conn->recv_timeout > 0) {
    struct timeval tval = {.tv_sec = conn->recv_timeout / 1000,
                           .tv_usec = (conn->recv_timeout % 1000) * 1000};
    if (setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tval,
                   sizeof(tval)) == -1) {
      PRINTERROR("setsockopt: failed to set SO_RCVTIMEO (%s)", strerror(errno));
      close(clientfd);
      return ERR_TCP_ACCEPT; // TODO: better error code?
    }
  }

  // keep this if block separate since the compiler can optimize it away
  if (SOCK_CLOEXEC == 0) {
    flags = fcntl(clientfd, F_GETFD);
    if (flags < 0) {
      PRINTERROR("fcntl: failed to get flags (%s)", strerror(errno));
      flags = 0;
    }
    flags |= FD_CLOEXEC;
    if (fcntl(clientfd, F_SETFD, flags) == -1)
      PRINTERROR("fcntl: failed to set O_CLOEXEC (%s)", strerror(errno));
  }

  /** make this socket non-blocking */
  conn->sock_flags = flags = fcntl(clientfd, F_GETFL, 0);
  fcntl(clientfd, F_SETFL, flags | O_NONBLOCK);

  close(conn->sockfd); // close the listening socket
  conn->sockfd = -1;
  PRINTDEBUG("new connection accepted on fd=%d", clientfd);

  return ERR_SUCCESS;
}

/**
 * @param[in] conn The client connection context.
 * @return An `error_t` status code.
 *
 * Send the message present in `conn->msgbuf` to the peer. All messages with
 * application-level payloads are encrypted.
 *
 * The caller must indicate the type of message by setting the `msgbuf->type`
 * field; failing to do so would result in a protocol violation/failure.
 *
 * If a failure occurs before all of the `conn->msgbuf->len` bytes of data are
 * sent (either because of a timeout or other error), the function returns an
 * `ERR_TCP_SEND`.
 */
static error_t server_send(zt_server_connection_t *conn) {
  error_t ret;
  size_t len, tosend, taglen;
  uint8_t *rawptr;
  bool is_encrypted;

  ASSERT(conn);
  ASSERT(conn->state > SERVER_CONN_INIT && conn->state < SERVER_DONE);
  ASSERT(conn->msgbuf);

  if (zt_msg_data_len(conn->msgbuf) > ZT_MAX_TRANSFER_SIZE) {
    PRINTERROR("message data too large (%zu bytes)",
               zt_msg_data_len(conn->msgbuf));
    return ERR_REQUEST_TOO_LARGE;
  }

  is_encrypted = (zt_msg_type(conn->msgbuf) != MSG_HANDSHAKE);

  len = zt_msg_data_len(conn->msgbuf);

  rawptr = zt_msg_data_ptr(conn->msgbuf);
  rawptr[len++] = MSG_END; // data END marker

  zt_msg_set_len(conn->msgbuf, len); /* update length in header */

  if (is_encrypted) {
    if ((ret = vcry_aead_encrypt(rawptr + ZT_MSG_HEADER_SIZE, len, rawptr,
                                 ZT_MSG_HEADER_SIZE, rawptr, &tosend)) !=
        ERR_SUCCESS) {
      PRINTERROR("encryption failed");
      return ret;
    }
  } else {
    tosend = len + ZT_MSG_HEADER_SIZE;
  }

  if (zt_server_tcp_send(conn, rawptr, tosend) != 0) {
    PRINTERROR("failed to send %zu bytes to peer_id=%s (%s)", tosend,
               config.peer_id, strerror(errno));
    return ERR_TCP_SEND;
  }

  zt_msg_set_len(conn->msgbuf, 0);

  return ERR_SUCCESS;
}

/**
 * @param[in] conn The server connection context.
 * @param[in] expect The expected message type.
 * @return An `error_t` status code.
 *
 * Receive a message from the peer. The caller must indicate the expected
 * message type by passing it as the `expect` parameter; failing to do so would
 * result in a protocol violation/failure.
 *
 * The amount of payload data to be read is indicated by a fixed-size header
 * prefix. If a failure occurs before all of this payload data is received
 * (either because of a timeout or other error), the function returns an error
 * code and sets the message length to 0.
 *
 * Encrypted payload data is decrypted in-place in `conn->msgbuf->data[]`.
 */
static error_t server_recv(zt_server_connection_t *conn, zt_msg_type_t expect) {
  error_t ret = ERR_SUCCESS;
  ssize_t nread;
  size_t taglen, datalen, i;
  uint8_t *rawptr, *dataptr;
  bool is_encrypted;

  ASSERT(conn);
  ASSERT(conn->state > SERVER_CONN_INIT && conn->state <= SERVER_DONE);
  ASSERT(conn->msgbuf);

  rawptr = zt_msg_raw_ptr(conn->msgbuf);
  dataptr = zt_msg_data_ptr(conn->msgbuf);

  /** read the msg header */
  nread = zt_server_tcp_recv(conn, rawptr, ZT_MSG_HEADER_SIZE, NULL);
  if (nread < 0) {
    PRINTERROR("failed to read data from peer_id=%s (%s)", config.peer_id,
               strerror(errno));
    ret = ERR_TCP_RECV;
    goto out;
  }
  if (nread != ZT_MSG_HEADER_SIZE) {
    PRINTERROR("received malformed header");
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  if (!msg_type_isvalid(zt_msg_type(conn->msgbuf)) ||
      (expect != zt_msg_type(conn->msgbuf))) {
    PRINTERROR("invalid message type %u (expected %u)",
               zt_msg_type(conn->msgbuf), expect);
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  is_encrypted = (zt_msg_type(conn->msgbuf) != MSG_HANDSHAKE);

  if (is_encrypted)
    vcry_get_aead_tag_len(&taglen);
  else
    taglen = 0;
  datalen = zt_msg_data_len(conn->msgbuf) + taglen;

  /** read msg payload */
  nread = zt_server_tcp_recv(conn, dataptr, datalen, NULL);
  if (nread < 0) {
    PRINTERROR("failed to read data from peer_id=%s (%s)", config.peer_id,
               strerror(errno));
    ret = ERR_TCP_RECV;
    goto out;
  }
  if (nread != datalen) {
    PRINTERROR("received only %zu bytes of payload (expected %zu bytes)", nread,
               datalen);
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  /** decrypt encrypted payload */
  if (is_encrypted) {
    if ((ret = vcry_aead_decrypt(rawptr, datalen, rawptr, ZT_MSG_HEADER_SIZE,
                                 rawptr, &nread)) != ERR_SUCCESS) {
      PRINTERROR("decryption failed");
      goto out;
    }
  }

  /**
   * Remove message padding - this loop intentionally iterates through
   * the entire message payload to avoid leaking the padding length due
   * to timing differences
   */
  for (i = nread; i > 0; --i)
    if (dataptr[i - 1] == MSG_END)
      nread = i - 1;

out:
  if (unlikely(ret))
    zt_msg_set_len(conn->msgbuf, 0);
  else
    zt_msg_set_len(conn->msgbuf, nread);
  return ret;
}
