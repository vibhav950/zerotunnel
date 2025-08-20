
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "server.h"

#include "common/log.h"
#include "common/progressbar.h"
#include "common/prompts.h"
#include "common/tty_io.h"
#include "ip.h"
#include "vcry.h"
#include "ztlib.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#define accept4(a, b, c, d) accept(a, b, c);
#endif

// clang-format off
static const char serverstate_names[][20] = {
    [SERVER_NONE]           = "SERVER_NONE",
    [SERVER_CONN_INIT]      = "SERVER_CONN_INIT",
    [SERVER_CONN_LISTEN]    = "SERVER_CONN_LISTEN",
    [SERVER_AUTH_RESPOND]   = "SERVER_AUTH_RESPOND",
    [SERVER_AUTH_COMPLETE]  = "SERVER_AUTH_COMPLETE",
    [SERVER_COMMIT]         = "SERVER_COMMIT",
    [SERVER_TRANSFER]       = "SERVER_TRANSFER",
    [SERVER_DONE]           = "SERVER_DONE"
};
// clang-format on

#define SERVERSTATE_CHANGE(cur, next) (void)(cur = next)

static inline const char *get_serverstate_name(ZT_SERVER_STATE state) {
  if (likely(state >= SERVER_NONE && state <= SERVER_DONE))
    return serverstate_names[state];
  else
    return "Unknown";
}

static inline ATTRIBUTE_NONNULL(1, 2) const
    char *get_ip_str(const struct sockaddr *sa, char *buf, size_t buflen) {
  switch (sa->sa_family) {
#ifdef USE_IPV6
  case AF_INET6:
    return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, buf,
                     buflen);
#endif
  case AF_INET:
    return inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, buf,
                     buflen);
  default:
    return NULL; /* unsupported address family */
  }
}

static err_t server_setup_host(zt_server_connection_t *conn,
                               struct zt_addrinfo **ai_list) {
  err_t ret = ERR_SUCCESS;
  int status, af, preferred_family = -1;
  struct zt_addrinfo *preferred = NULL, *preferred_tail = NULL;
  struct zt_addrinfo *unpreferred = NULL, *unpreferred_tail = NULL;
  struct zt_addrinfo *ai_cur;
  struct addrinfo hints, *res = NULL, *cur;
  size_t saddr_len;
  bool use_ipv6 = false;
  void *addr_ptr;
  char ipstr[INET6_ADDRSTRLEN];

  ASSERT(conn);
  ASSERT(conn->state == SERVER_CONN_INIT);

#ifdef USE_IPV6
  /* Check for IPv6 availability */
  if (!GlobalConfig.flag_ipv4_only) {
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s != -1) {
      use_ipv6 = true;
      close(s);
    }
  }
#endif

  af = zt_choose_ip_family(!GlobalConfig.flag_ipv6_only, use_ipv6);
  if (af < 0) {
    log_error(NULL, "could not choose a suitable address family");
    ret = ERR_BAD_ARGS;
    goto out;
  }

  if (af == AF_UNSPEC) {
    preferred_family =
        GlobalConfig.preferred_family == '4' ? AF_INET : AF_INET6;
  }

  zt_memset(&hints, 0, sizeof(hints));
  hints.ai_family = af;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  if (status = getaddrinfo(conn->hostname, conn->listen_port, &hints, &res)) {
    const char *errstr =
        (status == EAI_SYSTEM) ? strerror(errno) : gai_strerror(status);

    log_error(NULL, "getaddrinfo: error resolving local address '%s:%s' (%s)",
              conn->hostname, conn->listen_port, errstr);
    ret = ERR_INTERNAL;
    goto out;
  }

  /**
   * Build the list of zt_addrinfo while respecting the preferred_family if the
   * address family is AF_UNSPEC
   */
  *ai_list = NULL;
  for (cur = res; cur != NULL; cur = cur->ai_next) {
    size_t total_size;

    if (cur->ai_family == AF_INET) {
      saddr_len = sizeof(struct sockaddr_in);
    }
#ifdef USE_IPV6
    else if (cur->ai_family == AF_INET6) {
      saddr_len = sizeof(struct sockaddr_in6);
    }
#endif
    else {
      continue; /* ignore unsupported address families */
    }

    /* Ignore elements without required address info */
    if (!cur->ai_addr || !(cur->ai_addrlen > 0))
      continue;

    /* Ignore elements with bad address length */
    if ((size_t)cur->ai_addrlen < saddr_len)
      continue;

    total_size = sizeof(struct zt_addrinfo) + saddr_len;
    ai_cur = (struct zt_addrinfo *)zt_malloc(total_size);
    if (!ai_cur) {
      ret = ERR_MEM_FAIL;
      goto out;
    }

    /* copy each member */
    ai_cur->ai_flags = cur->ai_flags;
    ai_cur->ai_family = cur->ai_family;
    ai_cur->ai_socktype = cur->ai_socktype;
    ai_cur->ai_protocol = cur->ai_protocol;
    ai_cur->ai_addrlen = cur->ai_addrlen;
    ai_cur->ai_canonname = NULL;
    ai_cur->ai_addr = NULL;
    ai_cur->ai_next = NULL;
    ai_cur->total_size = total_size;

    ai_cur->ai_addr = (void *)((char *)ai_cur + sizeof(struct zt_addrinfo));
    memcpy(ai_cur->ai_addr, cur->ai_addr, saddr_len);

    if (cur->ai_family == preferred_family) {
      if (preferred_tail)
        preferred_tail->ai_next = ai_cur;
      else
        preferred = ai_cur;
      preferred_tail = ai_cur;
    } else {
      if (unpreferred_tail)
        unpreferred_tail->ai_next = ai_cur;
      else
        unpreferred = ai_cur;
      unpreferred_tail = ai_cur;
    }

    if (cur->ai_family == AF_INET)
      addr_ptr = &((struct sockaddr_in *)cur->ai_addr)->sin_addr;
#ifdef USE_IPV6
    else if (cur->ai_family == AF_INET6) {
      addr_ptr = &((struct sockaddr_in6 *)cur->ai_addr)->sin6_addr;
    }
#endif

    if (addr_ptr) {
      log_debug(NULL, "Resolved %s to %s", conn->hostname,
                inet_ntop(cur->ai_family, addr_ptr, ipstr, sizeof(ipstr)));
    }
  }

  /* Merge the two lists based on preference (if any applies) */
  if (preferred) {
    preferred_tail->ai_next = unpreferred;
    *ai_list = preferred;
  } else {
    *ai_list = unpreferred;
  }

out:
  /* If there was an error, free the zt_addrinfo list before exiting */
  if (ret) {
    zt_addrinfo_free(*ai_list);
    *ai_list = NULL;
  }
  freeaddrinfo(res);
  return ret;
}

static err_t server_tcp_listen(zt_server_connection_t *conn,
                               struct zt_addrinfo *ai_list) {
  err_t ret = ERR_SUCCESS;
  struct zt_addrinfo *ai_cur, *ai_estab = NULL;
  int sockfd, optval;

  ASSERT(conn);
  ASSERT(conn->state == SERVER_CONN_INIT);
  ASSERT(ai_list);

  for (ai_cur = ai_list; ai_cur; ai_cur = ai_cur->ai_next) {
    (sockfd = socket(ai_cur->ai_family, ai_cur->ai_socktype | SOCK_CLOEXEC,
                     ai_cur->ai_protocol));
    if (sockfd < 0)
      continue; /* failed -- try next candidate */
    if (SOCK_CLOEXEC == 0) {
      /* SOCK_CLOEXEC isn't supported, set O_CLOEXEC using fcntl */
      int flags = fcntl(sockfd, F_GETFD);
      if (flags < 0) {
        log_error(NULL, "fcntl: failed to get flags (%s)", strerror(errno));
        flags = 0;
      }
      flags |= FD_CLOEXEC;
      if (fcntl(sockfd, F_SETFD, flags) == -1)
        log_error(NULL, "fcntl: failed to set O_CLOEXEC (%s)", strerror(errno));
    }

    optval = 1;
    (void)setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval,
                     sizeof(optval));

    optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval,
                   sizeof(optval)) == -1) {
      log_error(NULL, "setsockopt: failed to set SO_KEEPALIVE (%s)",
                strerror(errno));
    }

    if (bind(sockfd, ai_cur->ai_addr, ai_cur->ai_addrlen) == 0)
      break; /* success */
    else
      log_error(NULL, "bind: failed to bind socket (%s)", strerror(errno));

    /* try to enable TFO */
    if (conn->fl_tcp_fastopen) {
#if defined(TCP_FASTOPEN)
      optval = 5; /* allow maximum 5 pending SYNs */
      if (setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN, (void *)&optval,
                     sizeof(optval)) == -1) {
        log_error(NULL, "setsockopt: failed to set TCP_FASTOPEN (%s)",
                  strerror(errno));
        conn->fl_tcp_fastopen = false;
      }
#else
      log_error(NULL, "TCP_FASTOPEN cannot be enabled on this build");
      conn->fl_tcp_fastopen = false;
#endif
    }

    close(sockfd);
  }

  if (!ai_cur) {
    log_error(NULL, "could not bind to any suitable local address");
    ret = ERR_BAD_ARGS;
    goto out;
  }

  ai_estab = zt_malloc(ai_cur->total_size);
  if (!ai_estab) {
    ret = ERR_MEM_FAIL;
    goto out;
  }
  memcpy(ai_estab, ai_cur, ai_cur->total_size);
  ai_estab->ai_next = NULL;

  getnameinfo(ai_cur->ai_addr, ai_cur->ai_addrlen, conn->self.ip,
              INET6_ADDRSTRLEN, conn->self.port, sizeof(conn->self.port),
              NI_NUMERICHOST | NI_NUMERICSERV);
  log_debug(NULL, "bound to %s:%s", conn->self.ip, conn->self.port);

  /* make this socket nonblocking */
  conn->sockfd_flags = fcntl(sockfd, F_GETFL, 0);
  fcntl(sockfd, F_SETFL, conn->sockfd_flags | O_NONBLOCK);

  (void)listen(sockfd, 5); /* listen with a backlog of 5 */

  conn->ai_estab = ai_estab;
  conn->sockfd = sockfd;

out:
  zt_addrinfo_free(ai_list);
  return ret;
}

static err_t server_tcp_accept(zt_server_connection_t *conn) {
  int clientfd, flags;
  struct timeval tval;

  ASSERT(conn);
  ASSERT(conn->state == SERVER_CONN_LISTEN);
  ASSERT(conn->sockfd >= 0);

  conn->peer.addrlen = sizeof(conn->peer.addr);
  clientfd = accept4(conn->sockfd, (struct sockaddr *)&conn->peer.addr,
                     &conn->peer.addrlen, SOCK_CLOEXEC);
  if (clientfd < 0) {
    log_error(NULL, "accept4: failed to accept incoming connection (%s)",
              strerror(errno));
    if (errno == ENOSYS) {
      /**
       * On Linux <= 2.6.28 accept4() fails with `ENOSYS`; fallback to accept()
       * Thanks to https://github.com/python/cpython/issues/54324
       */
      log_debug(NULL, "accept4 not supported, falling back to accept()");
      conn->peer.addrlen = sizeof(conn->peer.addr);
      clientfd = accept(conn->sockfd, (struct sockaddr *)&conn->peer.addr,
                        &conn->peer.addrlen);
      if (clientfd < 0) {
        log_error(NULL, "accept: failed to accept incoming connection (%s)",
                  strerror(errno));
        close(conn->sockfd);
        return ERR_TCP_ACCEPT;
      }
    }
  }
  conn->peer.fd = clientfd;

  tval.tv_sec = conn->send_timeout / 1000;
  tval.tv_usec = (conn->send_timeout % 1000) * 1000;
  if (setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tval,
                 sizeof(tval)) == -1) {
    log_error(NULL, "setsockopt: failed to set SO_SNDTIMEO (%s)",
              strerror(errno));
    close(clientfd);
    return ERR_TCP_ACCEPT; // TODO: better error code?
  }

  tval.tv_sec = conn->recv_timeout / 1000;
  tval.tv_usec = (conn->recv_timeout % 1000) * 1000;
  if (setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tval,
                 sizeof(tval)) == -1) {
    log_error(NULL, "setsockopt: failed to set SO_RCVTIMEO (%s)",
              strerror(errno));
    close(clientfd);
    return ERR_TCP_ACCEPT; // TODO: better error code?
  }

  /* Keep this if block separate since the compiler can optimize it away */
  if (SOCK_CLOEXEC == 0) {
    flags = fcntl(clientfd, F_GETFD);
    if (flags < 0) {
      log_error(NULL, "fcntl: failed to get flags (%s)", strerror(errno));
      flags = 0;
    }
    flags |= FD_CLOEXEC;
    if (fcntl(clientfd, F_SETFD, flags) == -1)
      log_error(NULL, "fcntl: failed to set O_CLOEXEC (%s)", strerror(errno));
  }

  /* make this socket non-blocking */
  conn->peer.fd_flags = flags = fcntl(clientfd, F_GETFL, 0);
  fcntl(clientfd, F_SETFL, flags | O_NONBLOCK);

  close(conn->sockfd); /* close the listening socket */

  getnameinfo((const struct sockaddr *)&conn->peer.addr, conn->peer.addrlen,
              conn->peer.ip, sizeof(conn->peer.ip), conn->peer.port,
              sizeof(conn->peer.port), NI_NUMERICHOST | NI_NUMERICSERV);
  log_debug(NULL, "new connection accepted on fd=%d (from %s:%s)", clientfd,
            conn->peer.ip, conn->peer.port);

  return ERR_SUCCESS;
}

/**
 * @param[in] conn The client connection context.
 * @return An `err_t` status code.
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
static err_t server_send(zt_server_connection_t *conn) {
  err_t ret;
  size_t len, tosend, taglen;
  uint8_t *rawptr, *dataptr;
  bool is_encrypted;

  ASSERT(conn);
  ASSERT(conn->state > SERVER_CONN_INIT && conn->state <= SERVER_DONE);
  ASSERT(conn->msgbuf);

  if (MSG_DATA_LEN(conn->msgbuf) > ZT_MSG_MAX_RW_SIZE) {
    log_error(NULL, "message data too large (%zu bytes)",
              MSG_DATA_LEN(conn->msgbuf));
    return ERR_REQUEST_TOO_LARGE;
  }

  is_encrypted = !(MSG_TYPE(conn->msgbuf) &
                   (MSG_HANDSHAKE | MSG_AUTH_RETRY | MSG_HANDSHAKE_FIN));

  len = MSG_DATA_LEN(conn->msgbuf);

  dataptr = MSG_DATA_PTR(conn->msgbuf);
  dataptr[len++] = MSG_END_BYTE; /* data END marker */

  MSG_SET_LEN(conn->msgbuf, len); /* update length in header */

  rawptr = MSG_RAW_PTR(conn->msgbuf);

  if (is_encrypted) {
    tosend = ZT_MSG_MAX_RAW_SIZE - ZT_MSG_HEADER_SIZE;

    if ((ret = vcry_aead_encrypt(dataptr, len, rawptr, ZT_MSG_HEADER_SIZE,
                                 dataptr, &tosend)) != ERR_SUCCESS) {
      log_error(NULL, "encryption failed (%s)", zt_error_str(ret));
      return ret;
    }
  } else {
    tosend = len;
  }
  tosend += ZT_MSG_HEADER_SIZE; /* add header length */

  if (zt_server_tcp_send(conn, rawptr, tosend) != 0) {
    log_error(NULL, "failed to send %zu bytes to peer (%s)", tosend,
              strerror(errno));
    return ERR_TCP_SEND;
  }

  // MSG_SET_LEN(conn->msgbuf, 0);

  return ERR_SUCCESS;
}

#define msg_type_is_expected(msgtype, mask)                                    \
  (msgtype == MSG_ANY || (msgtype & mask) != 0)

/**
 * @param[in] conn The server connection context.
 * @param[in] expected_types A bitmask of the expected message types.
 * @return An `err_t` status code.
 *
 * Receive a message from the peer. The caller must indicate the expected
 * message type(s) using the @p expected_types bitmask. If
 * `expected_types=MSG_ANY`, any valid message type will be accepted.
 * If the received message type does not match the expected type(s),
 * the function returns an `ERR_INVALID_DATUM` error.
 *
 * The amount of payload data to be read is indicated by a fixed-size header
 * prefix. If a failure occurs before all of this payload data is received
 * (either because of a timeout or other error), the function returns an error
 * code and sets the message length to 0.
 *
 * Encrypted payload data is decrypted in-place in `conn->msgbuf->data[]`.
 */
static err_t server_recv(zt_server_connection_t *conn,
                         zt_msg_type_t expected_types) {
  err_t ret = ERR_SUCCESS;
  ssize_t nread;
  size_t taglen, datalen, i;
  uint8_t *p, *datap;
  bool is_encrypted;

  ASSERT(conn);
  ASSERT(conn->state > SERVER_CONN_INIT && conn->state <= SERVER_DONE);
  ASSERT(conn->msgbuf);

  p = MSG_RAW_PTR(conn->msgbuf);

  /** Read the msg header */
  nread = zt_server_tcp_recv(conn, p, ZT_MSG_HEADER_SIZE, NULL);
  if (nread < 0) {
    log_error(NULL, "failed to read TCP data (%s)", strerror(errno));
    ret = ERR_TCP_RECV;
    goto out;
  }
  if (nread != ZT_MSG_HEADER_SIZE) {
    log_error(NULL, "received malformed header (invalid length)");
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  if (!msg_type_isvalid(MSG_TYPE(conn->msgbuf))) {
    log_error(NULL, "received malformed header (invalid type)");
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  if (!msg_type_is_expected(MSG_TYPE(conn->msgbuf), expected_types)) {
    log_error(NULL, "bad message (expected %u)", expected_types);
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  if (MSG_DATA_LEN(conn->msgbuf) == 0) {
    nread = 1;
    goto out;
  }

  is_encrypted = !(MSG_TYPE(conn->msgbuf) &
                   (MSG_HANDSHAKE | MSG_AUTH_RETRY | MSG_HANDSHAKE_FIN));

  taglen = is_encrypted ? vcry_get_aead_tag_len() : 0;
  datalen = MSG_DATA_LEN(conn->msgbuf) + taglen;

  /** If the msg is compressed, read the payload into `msgbuf._xbuf[]` */
  datap = MSG_FLAGS(conn->msgbuf) & MSG_FL_COMPRESSION
              ? MSG_XBUF_PTR(conn->msgbuf) + ZT_MSG_HEADER_SIZE
              : MSG_DATA_PTR(conn->msgbuf);

  /** Read msg payload */
  nread = zt_server_tcp_recv(conn, datap, datalen, NULL);
  if (nread < 0) {
    log_error(NULL, "failed to read TCP data (%s)", strerror(errno));
    ret = ERR_TCP_RECV;
    goto out;
  }
  if (nread != datalen) {
    log_error(NULL, "received only %zu bytes of payload (expected %zu bytes)",
              nread, datalen);
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  /** Decrypt encrypted payload */
  if (is_encrypted) {
    nread =
        (MSG_FLAGS(conn->msgbuf) & MSG_FL_COMPRESSION ? ZT_MSG_XBUF_SIZE
                                                      : ZT_MSG_MAX_RAW_SIZE) -
        (ZT_MSG_HEADER_SIZE + ZT_MSG_SUFFIX_SIZE);

    if ((ret = vcry_aead_decrypt(datap, datalen, p, ZT_MSG_HEADER_SIZE, datap,
                                 &nread)) != ERR_SUCCESS) {
      log_error(NULL, "decryption failed (%s)", zt_error_str(ret));
      goto out;
    }
  }

  zt_msg_flags_t flags = MSG_FLAGS(conn->msgbuf);
  if (flags & MSG_FL_PADDING) {
    /**
     * Remove message padding - this loop intentionally iterates through
     * the entire message payload to avoid leaking the padding length due
     * to timing differences
     */
    for (i = nread; i > 0; --i)
      if (datap[i - 1] == MSG_END_BYTE)
        nread = i;
  } else if (flags & MSG_FL_COMPRESSION) {
    const char *rptr = (const char *)datap;
    char *wptr = (char *)MSG_DATA_PTR(conn->msgbuf);

    nread = LZ4_decompress_safe(rptr, wptr, nread, ZT_MSG_MAX_RW_SIZE + 1);
    if (nread <= 0) {
      log_error(NULL, "LZ4_decompress_safe failed (returned %d)", nread);
      ret = ERR_INVALID_DATUM;
      goto out;
    }
    datap = MSG_DATA_PTR(conn->msgbuf);
  }

  if (unlikely(datap[nread - 1] != MSG_END_BYTE)) {
    log_error(NULL, "received malformed message (missing end marker)");
    ret = ERR_INVALID_DATUM;
    goto out;
  }

out:
  if (unlikely(ret))
    MSG_SET_LEN(conn->msgbuf, 0);
  else
    MSG_SET_LEN(conn->msgbuf, nread - 1);
  return ret;
}

static inline uint64_t filesize_unit_conv(uint64_t size) {
  if (size > SIZE_GB)
    return size / SIZE_GB;
  else if (size > SIZE_MB)
    return size / SIZE_MB;
  else if (size > SIZE_KB)
    return size / SIZE_KB;
  else
    return size; /* in bytes */
}

static inline const char *filesize_unit_str(uint64_t size) {
  if (size > SIZE_GB)
    return "GB";
  else if (size > SIZE_MB)
    return "MB";
  else if (size > SIZE_KB)
    return "KB";
  else
    return "bytes"; /* in bytes */
}

err_t zt_server_conn_alloc(zt_server_connection_t **conn) {
  size_t alloc_size;

  if (!conn)
    return ERR_NULL_PTR;

  alloc_size =
      sizeof(zt_server_connection_t) + sizeof(zt_msg_t) + ZT_MSG_XBUF_SIZE;
  if (!(*conn = zt_calloc(1, alloc_size)))
    return ERR_MEM_FAIL;

  (*conn)->msgbuf =
      (zt_msg_t *)((char *)(*conn) + sizeof(zt_server_connection_t));
  (*conn)->msgbuf->_xbuf =
      (uint8_t *)((char *)(*conn) + sizeof(zt_server_connection_t) +
                  sizeof(zt_msg_t));

  (*conn)->sockfd = -1;
  (*conn)->peer.fd = -1;

  return ERR_SUCCESS;
}

void zt_server_conn_dealloc(zt_server_connection_t *conn) {
  if (!conn)
    return;

  zt_free(conn);
}

err_t zt_server_run(zt_server_connection_t *conn, void *args ATTRIBUTE_UNUSED,
                    bool *done) {
  err_t ret = ERR_SUCCESS;
  auth_type_t auth_type;
  zt_fio_t *fileptr;
  char port[6];

  if (!conn || !done)
    return ERR_NULL_PTR;

  if (zt_get_hostid(&conn->self.authid) != 0)
    return ERR_INTERNAL;

  conn->hostname = GlobalConfig.hostname ? GlobalConfig.hostname : "0.0.0.0";

  if (conn->fl_explicit_port) {
    snprintf(port, sizeof(port), "%u", GlobalConfig.service_port);
    conn->listen_port = port;
  } else {
    conn->listen_port = ZT_DEFAULT_LISTEN_PORT;
  }

  conn->idle_timeout = GlobalConfig.idle_timeout > 0
                           ? GlobalConfig.idle_timeout
                           : ZT_SERVER_TIMEOUT_IDLE_DEFAULT;
  conn->recv_timeout = GlobalConfig.recv_timeout > 0
                           ? GlobalConfig.recv_timeout
                           : ZT_SERVER_TIMEOUT_RECV_DEFAULT;
  conn->send_timeout = GlobalConfig.send_timeout > 0
                           ? GlobalConfig.send_timeout
                           : ZT_SERVER_TIMEOUT_SEND_DEFAULT;

  conn->state = SERVER_CONN_INIT;

  *done = false;

  /* main message loop */
  while (1) {
    switch (conn->state) {
    case SERVER_CONN_INIT: {
      struct zt_addrinfo *ai_list = NULL;
      uint32_t firstword;

      if ((ret = server_setup_host(conn, &ai_list)) != ERR_SUCCESS)
        return ret;

      if ((ret = server_tcp_listen(conn, ai_list)) != ERR_SUCCESS)
        return ret;

      firstword = conn->self.authid.words[0];

      tty_printf(get_cli_prompt(OnServerListening), conn->self.ip,
                 conn->self.port, firstword);

      SERVERSTATE_CHANGE(conn->state, SERVER_CONN_LISTEN);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_CONN_LISTEN: {
      bool ok = zt_tcp_io_waitfor_read(conn->sockfd, conn->idle_timeout);

      if (!ok) {
        log_error(NULL,
                  "an error occurred while waiting for incoming connections "
                  "on the listening socket (%s)",
                  strerror(errno));
        ret = ERR_TCP_ACCEPT;
        goto cleanup1;
      }

      if ((ret = server_tcp_accept(conn)) != ERR_SUCCESS)
        goto cleanup1;

      SERVERSTATE_CHANGE(conn->state, SERVER_AUTH_RESPOND);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_AUTH_RESPOND: {
      uint8_t *sndbuf[2], *rcvbuf;
      size_t sndlen[2], rcvlen;
      passwd_id_t passwd_id;
      static struct passwd *master_pass = NULL;

      if (!conn->pending) {
        if (server_recv(conn, MSG_HANDSHAKE) != ERR_SUCCESS) {
          ret = ERR_TCP_RECV;
          goto cleanup2;
        }
      }
      conn->pending = false;

      rcvlen = MSG_DATA_LEN(conn->msgbuf);
      rcvbuf = MSG_DATA_PTR(conn->msgbuf);

      if (rcvlen <
          AUTHID_BYTES_LEN + sizeof(passwd_id_t) + sizeof(ciphersuite_t)) {
        log_error(NULL, "received malformed handshake header");
        ret = ERR_INVALID_DATUM;
        goto cleanup2;
      }

      memcpy(conn->peer.authid.bytes, rcvbuf, AUTHID_BYTES_LEN);
      rcvbuf += AUTHID_BYTES_LEN;

      memcpy(PTRV(&passwd_id), rcvbuf, sizeof(passwd_id_t));
      rcvbuf += sizeof(passwd_id_t);

      memcpy(PTRV(&auth_type), rcvbuf, sizeof(auth_type_t));
      rcvbuf += sizeof(auth_type_t);

      memcpy(PTRV(&conn->ciphersuite), rcvbuf, sizeof(ciphersuite_t));
      rcvbuf += sizeof(ciphersuite_t);

      rcvlen -= AUTHID_BYTES_LEN + sizeof(passwd_id_t) + sizeof(ciphersuite_t);

      if (auth_type != GlobalConfig.auth_type) {
        tty_printf(get_cli_prompt(OnAuthTypeMismatch), auth_type,
                   GlobalConfig.auth_type);
        ret = ERR_HSHAKE_ABORTED;
        goto cleanup2;
      }

      /* Load the master password */
      if (!master_pass) {
        passwd_id = zt_auth_passwd_get(
            GlobalConfig.passwdfile, GlobalConfig.auth_type,
            GlobalConfig.passwd_bundle_id, passwd_id, &master_pass);
      }

      if (conn->expected_passwd.expect &&
          (conn->expected_passwd.id != passwd_id)) {
        /**
         * The client has responded to a password renegotiation request, but
         * the password Id does not match the expected one
         */
        log_error(NULL, "could not negotiate a usable password -- aborting!");
        ret = ERR_HSHAKE_ABORTED;
        goto cleanup2;
      } else if (passwd_id < 0 && GlobalConfig.auth_type == KAPPA_AUTHTYPE_1) {
        /**
         * KAPPA1 authentication failure -- this can happen due to the passwddb
         * files becoming out-of-sync so we ask the user if we may renegotiate a
         * new password
         */
        log_error(NULL, "authentication failed for hostname '%s'",
                  conn->hostname);

        if (++conn->auth_retries > MAX_AUTH_RETRY_COUNT) {
          log_error(NULL, "too many authentication retries -- aborting!");
          ret = ERR_HSHAKE_ABORTED;
          goto cleanup2;
        }

        if (!tty_get_answer_is_yes(get_cli_prompt(OnBadPasswdIdentifier))) {
          ret = ERR_HSHAKE_ABORTED;
          goto cleanup2;
        }

        log_info(NULL, "Retrying handshake with a new password...");

        passwd_id_t pwid = zt_auth_passwd_load(GlobalConfig.passwdfile,
                                               GlobalConfig.passwd_bundle_id,
                                               -1, &master_pass);
        if (pwid < 0) {
          log_error(NULL, "failed to load a new password for hostname '%s'",
                    conn->hostname);
          ret = ERR_HSHAKE_ABORTED;
          goto cleanup2;
        }

        /**
         * Successfully loaded a new password; save it and request the
         * peer to retry the handshake with the corresponding passwdId
         */
        conn->expected_passwd.expect = true;
        conn->expected_passwd.id = pwid;

        MSG_MAKE(conn->msgbuf, MSG_AUTH_RETRY, PTRV(&pwid), sizeof(passwd_id_t),
                 0);
        if ((ret = server_send(conn)) != ERR_SUCCESS)
          goto cleanup2;

        /* We will expect a new MSG_HANDSHAKE from the client with a
         * confirmation that the client chose the expected password */
        SERVERSTATE_CHANGE(conn->state, SERVER_AUTH_RESPOND);
        break;
      } else if (passwd_id < 0) {
        /* KAPPA0 and KAPPA2 -- failed to get a password from the user */
        log_error(NULL, "failed to load master password");
        ret = ERR_INTERNAL; // FIXME: better error code?
        goto cleanup2;
      }

      /* Setup the VCRY module now that we have the required parameters */
      if ((ret = vcry_module_init()) != ERR_SUCCESS) {
        log_error(NULL, "vcry_module_init : %s", zt_error_str(ret));
        goto cleanup2;
      }

      vcry_set_role_responder();

      if ((ret = vcry_set_authpass(master_pass->pw, master_pass->pwlen)) !=
          ERR_SUCCESS) {
        log_error(NULL, "vcry_set_authpass : %s", zt_error_str(ret));
        zt_auth_passwd_free(master_pass, NULL);
        goto cleanup2;
      }

      /* We don't need the master passwd anymore -- don't keep it in memory */
      zt_auth_passwd_free(master_pass, NULL);
      master_pass = NULL;

      int vcry_algs[6];
      const char *csname;
      // clang-format off
      csname = zt_cipher_suite_info(conn->ciphersuite,
                                    &vcry_algs[0], &vcry_algs[1], &vcry_algs[2],
                                    &vcry_algs[3], &vcry_algs[4], &vcry_algs[5]);
      if (!csname) {
        ret = ERR_INVALID;
        goto cleanup2;
      }
      log_info(NULL, "using ciphersuite %s", csname);

      if ((ret = vcry_set_crypto_params(
               vcry_algs[0], vcry_algs[1], vcry_algs[2],
               vcry_algs[3], vcry_algs[4], vcry_algs[5])) != ERR_SUCCESS) {
        log_error(NULL, "vcry_set_crypto_params : %s", zt_error_str(ret));
        goto cleanup2;
      }
      // clang-format on

      if ((ret = vcry_handshake_respond(rcvbuf, rcvlen, &sndbuf[0],
                                        &sndlen[0])) != ERR_SUCCESS) {
        log_error(NULL, "vcry_handshake_respond : %s", zt_error_str(ret));
        goto cleanup2;
      }

      if ((ret = vcry_derive_session_key()) != ERR_SUCCESS) {
        log_error(NULL, "vcry_derive_session_key : %s", zt_error_str(ret));
        zt_free(sndbuf[0]);
        goto cleanup2;
      }

      if ((ret = vcry_responder_verify_initiate(
               &sndbuf[1], &sndlen[1], conn->self.authid.bytes,
               conn->peer.authid.bytes, AUTHID_BYTES_LEN, AUTHID_BYTES_LEN)) !=
          ERR_SUCCESS) {
        log_error(NULL, "vcry_responder_verify_initiate : %s",
                  zt_error_str(ret));
        zt_free(sndbuf[0]);
        goto cleanup2;
      }

      /** Make the handshake response message */
      uint8_t *p = MSG_DATA_PTR(conn->msgbuf);
      memcpy(p, conn->self.authid.bytes, AUTHID_BYTES_LEN);
      p += AUTHID_BYTES_LEN;
      memcpy(p, sndbuf[0], sndlen[0]);
      p += sndlen[0];
      memcpy(p, sndbuf[1], sndlen[1]);

      MSG_SET_LEN(conn->msgbuf, AUTHID_BYTES_LEN + sndlen[0] + sndlen[1]);
      MSG_SET_TYPE(conn->msgbuf, MSG_HANDSHAKE);

      zt_free(sndbuf[0]);
      zt_free(sndbuf[1]);

      if ((ret = server_send(conn)) != ERR_SUCCESS)
        goto cleanup2;

      SERVERSTATE_CHANGE(conn->state, SERVER_AUTH_COMPLETE);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_AUTH_COMPLETE: {
      uint8_t *rcvbuf;
      size_t rcvlen;

      if ((ret = server_recv(conn, MSG_HANDSHAKE | MSG_HANDSHAKE_FIN)) !=
          ERR_SUCCESS) {
        goto cleanup2;
      }

      if (MSG_TYPE(conn->msgbuf) == MSG_HANDSHAKE) {
        conn->pending = true;
        goto retryhandshake;
      }

      rcvbuf = MSG_DATA_PTR(conn->msgbuf);
      rcvlen = MSG_DATA_LEN(conn->msgbuf);

      if (rcvlen < VCRY_VERIFY_MSG_LEN) {
        log_error(NULL, "received malformed verification message");
        ret = ERR_INVALID_DATUM;
        goto cleanup2;
      }

      ret = vcry_responder_verify_complete(rcvbuf, conn->self.authid.bytes,
                                           conn->peer.authid.bytes,
                                           AUTHID_BYTES_LEN, AUTHID_BYTES_LEN);
      switch (ret) {
      case ERR_SUCCESS:
        break; /* successful */
      case ERR_AUTH_FAIL:
        goto retryhandshake;
      default:
        log_error(NULL, "vcry_responder_verify_complete : %s",
                  zt_error_str(ret));
        goto cleanup2;
      }

      MSG_MAKE(conn->msgbuf, MSG_HANDSHAKE_FIN, NULL, 0, 0);

      if (server_send(conn) != ERR_SUCCESS)
        goto cleanup2;

      SERVERSTATE_CHANGE(conn->state, SERVER_COMMIT);
      break;

    retryhandshake:
      /**
       * @warning Failed to verify the established session key -- this could
       * be due to an incorrect password attempt or a possible
       * Man-In-The-Middle and the attacker guessed wrong! Alert the user of
       * this and ask whether to retry the handshake -- which would give the
       * user and his correspondent another password attempt and a would-be
       * attacker another chance to guess the password!
       */

      if (++conn->auth_retries > MAX_AUTH_RETRY_COUNT) {
        log_error(NULL, "too many authentication retries -- aborting!");
        ret = ERR_HSHAKE_ABORTED;
        goto cleanup2;
      }

      if (!tty_get_answer_is_yes(get_cli_prompt(OnIncorrectPasswdAttempt))) {
        ret = ERR_HSHAKE_ABORTED;
        goto cleanup2;
      }

      if (!conn->pending) {
        /* There was a verification failure on our end, ask the initiator to
         * retry authentication*/
        MSG_MAKE(conn->msgbuf, MSG_AUTH_RETRY, NULL, 0, 0);

        if ((ret = server_send(conn)) != ERR_SUCCESS)
          goto cleanup2;
      }

      /* Handshake will be restarted -- we need to init the module again */
      vcry_module_release();

      SERVERSTATE_CHANGE(conn->state, SERVER_AUTH_RESPOND);
      break;
    }

    case SERVER_COMMIT: {
      if ((ret = server_recv(conn, MSG_METADATA)) != ERR_SUCCESS)
        goto cleanup2;

      if (MSG_DATA_LEN(conn->msgbuf) != sizeof(zt_fileinfo_t)) {
        log_error(NULL, "received malformed metadata message");
        ret = ERR_INVALID_DATUM;
        goto cleanup2;
      }

      memcpy(PTRV(&conn->fileinfo), MSG_DATA_PTR(conn->msgbuf),
             sizeof(zt_fileinfo_t));

      conn->fileinfo.size = ntoh64(conn->fileinfo.size);
      conn->fileinfo.reserved = ntoh32(conn->fileinfo.reserved);

      off_t filesize = filesize_unit_conv(conn->fileinfo.size);
      const char *unit = filesize_unit_str(conn->fileinfo.size);

      tty_printf(get_cli_prompt(OnIncomingTransfer), conn->fileinfo.name,
                 filesize, unit);
      if (!tty_get_answer_is_yes(get_cli_prompt(OnFileTransferRequest))) {
        log_info(NULL, "shutting everything down...");
        goto cleanup2;
      }

      SERVERSTATE_CHANGE(conn->state, SERVER_TRANSFER);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_TRANSFER: {
      err_t rv;
      zt_fio_t fileptr;
      off_t remaining;

      if ((ret = zt_fio_open(&fileptr, GlobalConfig.filepath, FIO_WRONLY)) !=
          ERR_SUCCESS) {
        log_error(NULL, "failed to open file for writing");
        goto cleanup2;
      }

      if ((ret = zt_fio_write_allocate(&fileptr, conn->fileinfo.size)) !=
          ERR_SUCCESS) {
        log_error(NULL, "not enough disk space");
        zt_fio_close(&fileptr);
        goto cleanup2;
      }

      if (zt_progressbar_init() != 0)
        log_error(NULL, "failed to create progress bar");

      remaining = conn->fileinfo.size;
      zt_progressbar_begin(conn->peer.ip, conn->fileinfo.name, remaining);

      while (remaining > 0) {
        off_t writelen;

        if ((ret = server_recv(conn, MSG_FILEDATA)) != ERR_SUCCESS) {
          zt_fio_close(&fileptr);
          zt_progressbar_complete();
          zt_progressbar_destroy();
          goto cleanup2;
        }

        writelen = MIN(remaining, MSG_DATA_LEN(conn->msgbuf));
        rv = zt_fio_write(&fileptr, MSG_DATA_PTR(conn->msgbuf), writelen);
        if (rv != ERR_SUCCESS)
          break;

        zt_progressbar_update(writelen);
        remaining -= writelen;
      }
      zt_fio_close(&fileptr);
      zt_progressbar_complete();
      zt_progressbar_destroy();

      if (remaining) {
        log_error(NULL, "failed to write file to disk (%s)", zt_error_str(rv));
        ret = rv;
        goto cleanup2;
      }

      SERVERSTATE_CHANGE(conn->state, SERVER_DONE);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_DONE: {
      bool errfl = false;

      if ((ret = server_recv(conn, MSG_DONE)) != ERR_SUCCESS)
        goto cleanupfile;

      MSG_MAKE(conn->msgbuf, MSG_DONE, NULL, 0, 0);

      if ((ret = server_send(conn)) != ERR_SUCCESS)
        goto cleanupfile;

      SERVERSTATE_CHANGE(conn->state, SERVER_NONE);
      *done = true;
      goto cleanup2;
    }

    default: {
      log_error(NULL, "bad server state - %s",
                get_serverstate_name(conn->state));
      ret = ERR_INVALID;
      goto cleanup2;
    }
    } /* switch(conn->state) */
  } /* while(1) */

cleanupfile:
  zt_file_delete(GlobalConfig.filepath);

cleanup2:
  vcry_module_release();

  shutdown(conn->peer.fd, SHUT_RDWR);
  close(conn->peer.fd);

cleanup1:
  zt_addrinfo_free(conn->ai_estab);

  return ret;
}

err_t zt_server_enable_tcp_fastopen(zt_server_connection_t *conn, bool enable) {
  if (!conn)
    return ERR_NULL_PTR;

  if (conn->state != SERVER_NONE)
    return ERR_INVALID;

  conn->fl_tcp_fastopen = enable;
}

err_t zt_server_enable_explicit_port(zt_server_connection_t *conn,
                                     bool enable) {
  if (!conn)
    return ERR_NULL_PTR;

  if (conn->state != SERVER_NONE)
    return ERR_INVALID;

  conn->fl_explicit_port = enable;

  return ERR_SUCCESS;
}

err_t zt_server_enable_tcp_nodelay(zt_server_connection_t *conn, bool enable) {
  if (!conn)
    return ERR_NULL_PTR;

  if (conn->state != SERVER_NONE)
    return ERR_INVALID;

  conn->fl_tcp_nodelay = enable;

  return ERR_SUCCESS;
}
