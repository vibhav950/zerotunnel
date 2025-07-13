
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "server.h"

#include "common/prompts.h"
#include "common/tty_io.h"
#include "vcry.h"
#include "ztlib.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#define accept4(a, b, c, d) accept(a, b, c);
#endif

#define SERVERSTATE_CHANGE(cur, next) (void)(cur = next)

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

static inline const char *get_serverstate_name(ZT_SERVER_STATE state) {
  if (likely(state >= SERVER_NONE && state <= SERVER_DONE))
    return serverstate_names[state];
  else
    return "UNKNOWN";
}

static inline bool isIPv6(const char *addr) {
  if (!addr)
    return false; /* NULL defaults to 0.0.0.0 */
  char buf[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET6, addr, buf) == 0)
    return false;
  return true;
}

static err_t zt_server_setup_host(zt_server_connection_t *conn,
                                  struct zt_addrinfo **ai_list) {
  err_t ret = ERR_SUCCESS;
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

static err_t zt_server_tcp_listen(zt_server_connection_t *conn,
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

  getnameinfo(ai_cur->ai_addr, ai_cur->ai_addrlen, conn->self.address,
              INET6_ADDRSTRLEN, conn->self.port, sizeof(conn->self.port),
              NI_NUMERICHOST | NI_NUMERICSERV);
  PRINTDEBUG("bound to %s:%s", conn->self.address, conn->self.port);

  /* make this socket nonblocking */
  conn->sockfd_flags = fcntl(sockfd, F_GETFL, 0);
  fcntl(sockfd, F_SETFL, conn->sockfd_flags | O_NONBLOCK);

  (void)listen(sockfd, 5); // listen with a backlog of 5

  conn->ai_estab = ai_estab;
  conn->sockfd = sockfd;

exit:
  zt_addrinfo_free(ai_list);
  return ret;
}

static err_t zt_server_tcp_accept(zt_server_connection_t *conn) {
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
  conn->clientfd_flags = flags = fcntl(clientfd, F_GETFL, 0);
  fcntl(clientfd, F_SETFL, flags | O_NONBLOCK);

  close(conn->sockfd); // close the listening socket
  conn->sockfd = -1;
  PRINTDEBUG("new connection accepted on fd=%d", clientfd);

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

  is_encrypted =
      !(zt_msg_type(conn->msgbuf) & (MSG_HANDSHAKE | MSG_AUTH_RETRY));

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

#define msg_type_is_expected(msgtype, mask)                                    \
  (msgtype == MSG_ANY || (msgtype & mask))

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
    PRINTERROR("received malformed header (invalid length)");
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  if (!msg_type_isvalid(zt_msg_type(conn->msgbuf))) {
    PRINTERROR("received malformed header (invalid type)");
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  if (!msg_type_is_expected(zt_msg_type(conn->msgbuf), expected_types)) {
    PRINTERROR("bad message (expected %u)", expected_types);
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  is_encrypted =
      !(zt_msg_type(conn->msgbuf) & (MSG_HANDSHAKE | MSG_AUTH_RETRY));

  taglen = is_encrypted ? vcry_get_aead_tag_len() : 0;
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

static inline uint64_t filesize_unit_conv(uint64_t size) {
  if (size > SIZE_GB)
    return size / SIZE_GB;
  else if (size > SIZE_MB)
    return size / SIZE_MB;
  else if (size > SIZE_KB)
    return size / SIZE_KB;
  else
    return size; // in bytes
}

static inline const char *filesize_unit_str(uint64_t size) {
  if (size > SIZE_GB)
    return "GB";
  else if (size > SIZE_MB)
    return "MB";
  else if (size > SIZE_KB)
    return "KB";
  else
    return "bytes"; // in bytes
}

err_t zt_server_run(zt_server_connection_t *conn, void *args ATTRIBUTE_UNUSED,
                    bool *done) {
  err_t ret = ERR_SUCCESS;
  struct passwd *master_pass;
  zt_fio_t *fileptr;

  if (!conn || !done)
    return ERR_NULL_PTR;

  zt_memzero(conn, sizeof(zt_server_connection_t));

  if (zt_get_hostid(&conn->authid_self) != 0)
    return ERR_INTERNAL;

  /** Allocate memory for the primary server message buffer */
  if (!(conn->msgbuf = zt_malloc(sizeof(zt_msg_t))))
    return ERR_MEM_FAIL;

  /** Main message loop */
  while (1) {
    switch (conn->state) {
    case SERVER_CONN_INIT: {
      struct zt_addrinfo *ai_list = NULL;
      if ((ret = zt_server_setup_host(conn, &ai_list)) != ERR_SUCCESS)
        goto cleanup0;

      if ((ret = zt_server_tcp_listen(conn, ai_list)) != ERR_SUCCESS)
        goto cleanup0;

      tty_printf("%s(address=%s, port=%s, Id=%x)\n",
                 g_CLIPrompts[OnServerListening], conn->self.address,
                 conn->self.port, conn->authid_self.bytes);

      SERVERSTATE_CHANGE(conn->state, SERVER_CONN_LISTEN);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_CONN_LISTEN: {
      while (1) {
        int rv;
        timediff_t timeout_msec = conn->idle_timeout > 0
                                      ? conn->idle_timeout
                                      : -1; // wait indefinitely

        rv = zt_tcp_io_waitfor(conn->sockfd, timeout_msec, ZT_NETIO_READABLE);
        if (rv < 0) {
          PRINTERROR("an error occurred while waiting for incoming connections "
                     "on the listening socket (%s)",
                     strerror(errno));
          ret = ERR_TCP_ACCEPT;
          goto cleanup1;
        }

        if (rv > 0) {
          if ((ret = zt_server_tcp_accept(conn)) != ERR_SUCCESS)
            goto cleanup1;
          break; // client connection accepted
        }
      }

      SERVERSTATE_CHANGE(conn->state, SERVER_AUTH_RESPOND);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_AUTH_RESPOND: {
      uint8_t *sndbuf[2], *rcvbuf;
      size_t sndlen[2], rcvlen;
      passwd_id_t passwd_id;

      static int retrycount = 1;
      if (retrycount > MAX_AUTH_RETRY_COUNT) {
        PRINTERROR("too many handshake failures -- aborting!");
        ret = ERR_HSHAKE_ABORTED;
        goto cleanup2;
      }
      retrycount++;

      if (server_recv(conn, MSG_HANDSHAKE) != ERR_SUCCESS) {
        ret = ERR_TCP_RECV;
        goto cleanup2;
      }

      rcvlen = zt_msg_data_len(conn->msgbuf);
      rcvbuf = zt_msg_data_ptr(conn->msgbuf);

      if (rcvlen <
          AUTHID_BYTES_LEN + sizeof(passwd_id_t) + sizeof(ciphersuite_t)) {
        PRINTERROR("received malformed handshake header");
        ret = ERR_INVALID_DATUM;
        goto cleanup2;
      }

      zt_memcpy(conn->authid_peer.bytes, rcvbuf, AUTHID_BYTES_LEN);
      rcvbuf += AUTHID_BYTES_LEN;

      zt_memcpy(PTRV(&passwd_id), rcvbuf, sizeof(passwd_id_t));
      rcvbuf += sizeof(passwd_id_t);

      zt_memcpy(PTRV(&conn->ciphersuite), rcvbuf, sizeof(ciphersuite_t));
      rcvbuf += sizeof(ciphersuite_t);

      rcvlen -= AUTHID_BYTES_LEN + sizeof(passwd_id_t) + sizeof(ciphersuite_t);

      /** Load the master password */
      passwd_id = zt_auth_passwd_get(config.passwddb_file, config.auth_type,
                                     config.peer_id, passwd_id, &master_pass);

      if (conn->expected_passwd.expect &&
          (conn->expected_passwd.id != passwd_id)) {
        /**
         * The client has responded to a password renegotiation request, but
         * the password Id does not match the expected one
         */
        PRINTERROR("could not negotiate a usable password -- aborting!");
        ret = ERR_HSHAKE_ABORTED;
        goto cleanup2;
      } else if (passwd_id < 0 && config.auth_type == KAPPA_AUTHTYPE_1) {
        /**
         * KAPPA1 authentication failure -- this can happen due to the passwddb
         * files becoming out-of-sync so we ask the user if we may renegotiate a
         * new password
         */
        PRINTERROR("authentication failed for peer_id=%s", config.peer_id);

        if (!tty_get_answer_is_yes(g_CLIPrompts[OnBadPasswdIdentifier])) {
          ret = ERR_HSHAKE_ABORTED;
          goto cleanup2;
        }
        PRINTDEBUG("now trying to re-negotiate with a new password...");

        passwd_id_t pwid = zt_auth_passwd_load(
            config.passwddb_file, config.peer_id, -1, &master_pass);
        if (pwid < 0) {
          PRINTERROR("failed to load a new password for peer_id=%s",
                     config.peer_id);
          ret = ERR_HSHAKE_ABORTED;
          goto cleanup2;
        }

        /**
         * Successfully loaded a new password; save it and request the peer to
         * use this passwd
         */
        conn->expected_passwd.expect = true;
        conn->expected_passwd.id = pwid;

        zt_msg_make(conn->msgbuf, MSG_AUTH_RETRY, PTRV(&pwid),
                    sizeof(passwd_id_t));
        if ((ret = server_send(conn)) != ERR_SUCCESS)
          goto cleanup2;

        /* We will expect a new MSG_HANDSHAKE from the client with a
         * confirmation that the client chose the expected password */
        SERVERSTATE_CHANGE(conn->state, SERVER_AUTH_RESPOND);
        break;
      } else if (passwd_id < 0) {
        /** KAPPA0 and KAPPA2 -- failed to get a password from the user */
        PRINTERROR("failed to load master password");
        ret = ERR_INTERNAL; // FIXME: better error code?
        goto cleanup2;
      }

      /** Setup the VCRY module now that we have the required parameters */
      if ((ret = vcry_module_init()) != ERR_SUCCESS) {
        PRINTERROR("vcry_module_init() : %s", zt_strerror(ret));
        goto cleanup2;
      }

      vcry_set_role_responder();

      if ((ret = vcry_set_authpass(master_pass->pw, master_pass->pwlen)) !=
          ERR_SUCCESS) {
        PRINTERROR("vcry_set_authpass() : %s", zt_strerror(ret));
        zt_auth_passwd_free(master_pass);
        goto cleanup2;
      }
      /* we don't need the master passwd anymore -- why keep it in memory? */
      zt_auth_passwd_free(master_pass);

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
      PRINTINFO("using ciphersuite %s", csname);

      if ((ret = vcry_set_crypto_params(
               vcry_algs[0], vcry_algs[1], vcry_algs[2],
               vcry_algs[3], vcry_algs[4], vcry_algs[5])) != ERR_SUCCESS) {
        PRINTERROR("vcry_set_crypto_params() : %s", zt_strerror(ret));
        goto cleanup2;
      }
      // clang-format on

      if ((ret = vcry_handshake_respond(rcvbuf, rcvlen, &sndbuf[0],
                                        &sndlen[0])) != ERR_SUCCESS) {
        PRINTERROR("vcry_handshake_respond() : %s", zt_strerror(ret));
        goto cleanup2;
      }

      if ((ret = vcry_derive_session_key()) != ERR_SUCCESS) {
        PRINTERROR("vcry_derive_session_key() : %s", zt_strerror(ret));
        zt_free(sndbuf[0]);
        goto cleanup2;
      }

      if ((ret = vcry_responder_verify_initiate(
               &sndbuf[1], &sndlen[1], conn->authid_self.bytes,
               conn->authid_peer.bytes)) != ERR_SUCCESS) {
        PRINTERROR("vcry_responder_verify_initiate() : %s", zt_strerror(ret));
        zt_free(sndbuf[0]);
        goto cleanup2;
      }

      /** make the handshake response message */
      uint8_t *p = zt_msg_data_ptr(conn->msgbuf);
      zt_memcpy(p, conn->authid_self.bytes, AUTHID_BYTES_LEN);
      p += AUTHID_BYTES_LEN;
      zt_memcpy(p, sndbuf[0], sndlen[0]);
      p += sndlen[0];
      zt_memcpy(p, sndbuf[1], sndlen[1]);
      zt_msg_set_len(conn->msgbuf, AUTHID_BYTES_LEN + sndlen[0] + sndlen[1]);
      zt_msg_set_type(conn->msgbuf, MSG_HANDSHAKE);

      zt_free(sndbuf[0]);
      zt_free(sndbuf[1]);

      if ((ret = server_send(conn)) != ERR_SUCCESS)
        goto cleanup2;

      CLIENTSTATE_CHANGE(conn->state, SERVER_AUTH_COMPLETE);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_AUTH_COMPLETE: {
      uint8_t *rcvbuf;
      size_t rcvlen;

      if ((ret = server_recv(conn, MSG_HANDSHAKE)) != ERR_SUCCESS)
        goto cleanup2;

      rcvbuf = zt_msg_data_ptr(conn->msgbuf);
      rcvlen = zt_msg_data_len(conn->msgbuf);

      if (rcvlen < VCRY_VERIFY_MSG_LEN) {
        PRINTERROR("received malformed verification message");
        ret = ERR_INVALID_DATUM;
        goto cleanup2;
      }

      ret = vcry_responder_verify_complete(rcvbuf, conn->authid_self.bytes,
                                           conn->authid_peer.bytes);
      switch (ret) {
      case ERR_SUCCESS:
        break; /* successful */
      case ERR_AUTH_FAIL:
        goto retryhandshake;
      default:
        PRINTERROR("vcry_responder_verify_complete() : %s", zt_strerror(ret));
        goto cleanup2;
      }

      SERVERSTATE_CHANGE(conn->state, SERVER_COMMIT);
      break;

    retryhandshake:
      /**
       * [CAUTION!]
       * Failed to verify the established session key -- this could be due to an
       * incorrect password attempt or a possible Man-In-The-Middle and the
       * attacker guessed wrong!
       * Alert the user of this and ask whether to retry the handshake -- which
       * would give the user and his correspondent another password attempt and
       * a would-be attacker another chance to guess the password!
       */

      if (!tty_get_answer_is_yes(g_CLIPrompts[OnBadPasswdIdentifier])) {
        ret = ERR_HSHAKE_ABORTED;
        goto cleanup2;
      }

      /** handshake will be restarted */
      vcry_module_release();

      SERVERSTATE_CHANGE(conn->state, SERVER_AUTH_RESPOND);
      break;
    }

    case SERVER_COMMIT: {
      if ((ret = server_recv(conn, MSG_METADATA)) != ERR_SUCCESS)
        goto cleanup2;

      if (zt_msg_data_len(conn->msgbuf) != sizeof(zt_fileinfo_t)) {
        PRINTERROR("received malformed metadata message");
        ret = ERR_INVALID_DATUM;
        goto cleanup2;
      }

      zt_memcpy(PTRV(&conn->fileinfo), zt_msg_data_ptr(conn->msgbuf),
                sizeof(zt_fileinfo_t));

      conn->fileinfo.size = ntoh64(conn->fileinfo.size);
      conn->fileinfo.reserved = ntoh32(conn->fileinfo.reserved);

      off_t filesize = filesize_unit_conv(conn->fileinfo.size);
      const char *unit = filesize_unit_str(conn->fileinfo.size);
      tty_printf("Incoming file transfer (name = %s, size = %jd %s)\n",
                 filesize, unit);
      if (!tty_get_answer_is_yes(g_CLIPrompts[OnFileTransferRequest])) {
        PRINTINFO("shutting everything down...");
        goto cleanup2;
      }

      CLIENTSTATE_CHANGE(conn->state, SERVER_TRANSFER);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_TRANSFER: {
      err_t rv;
      zt_fio_t fileptr;
      off_t remaining;

      if ((ret = zt_fio_open(&fileptr, conn->fileinfo.name, FIO_WRONLY)) !=
          ERR_SUCCESS) {
        goto cleanup2;
      }

      if ((ret = zt_fio_write_allocate(&fileptr, conn->fileinfo.size)) !=
          ERR_SUCCESS) {
        zt_fio_close(&fileptr);
        goto cleanup2;
      }

      remaining = conn->fileinfo.size;
      while (remaining > 0) {
        off_t writelen;

        if ((ret = server_recv(conn, MSG_FILEDATA)) != ERR_SUCCESS) {
          zt_fio_close(&fileptr);
          goto cleanup2;
        }

        writelen = MIN(remaining, zt_msg_data_len(conn->msgbuf));
        rv = zt_fio_write(&fileptr, zt_msg_data_ptr(conn->msgbuf), writelen);
        if (rv != ERR_SUCCESS)
          break;
        remaining -= writelen;
      }

      zt_fio_close(&fileptr);

      if (remaining) {
        ret = rv;
        goto cleanup2;
      }

      CLIENTSTATE_CHANGE(conn->state, SERVER_DONE);
      ATTRIBUTE_FALLTHROUGH;
    }

    case SERVER_DONE: {
      bool errfl = false;

      if ((ret = server_recv(conn, MSG_DONE)) != ERR_SUCCESS) {
        ret = ERR_SUCCESS; // TODO: is this a reason for concern?
        errfl = true;
      }

      if (zt_msg_data_len(conn->msgbuf) == sizeof(DONE_MARKER) &&
          zt_memcmp(zt_msg_data_ptr(conn->msgbuf), DONE_MARKER,
                    sizeof(DONE_MARKER)) == 0) {
        PRINTINFO("transfer done! shutting down...");
      } else {
        ret = ERR_SUCCESS; // TODO: is this a reason for concern?
        errfl = true;
      }

      if (errfl) {
        PRINTERROR("abrupt shutdown by peer -- but the transfer was completed "
                   "successfully!");
      }

      CLIENTSTATE_CHANGE(conn->state, SERVER_NONE);
      *done = true;
      goto cleanup2;
    }

    default: {
      PRINTERROR("bad server state - %s", get_serverstate_name(conn->state));
      ret = ERR_INVALID;
      goto cleanup2;
    }
    } /* switch(conn->state) */
  } /* while(1) */

cleanup2:
  vcry_module_release();

  shutdown(conn->clientfd, SHUT_RDWR);
  close(conn->clientfd);
  conn->clientfd = -1;

cleanup1:
  zt_addrinfo_free(conn->ai_estab);
  conn->ai_estab = NULL;

cleanup0:
  zt_free(conn->msgbuf);
  conn->msgbuf = NULL;

  return ret;
}
