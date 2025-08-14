#include "client.h"
#include "ciphersuites.h"
#include "common/defines.h"
#include "common/log.h"
#include "common/progressbar.h"
#include "common/prompts.h"
#include "common/tty_io.h"
#include "vcry.h"
#include "ztlib.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// clang-format off
static const char clientstate_names[][20] = {
    [CLIENT_NONE]           = "CLIENT_NONE",
    [CLIENT_CONN_INIT]      = "CLIENT_CONN_INIT",
    [CLIENT_AUTH_INIT]      = "CLIENT_AUTH_INIT",
    [CLIENT_AUTH_COMPLETE]  = "CLIENT_AUTH_COMPLETE",
    [CLIENT_OFFER]          = "CLIENT_TRANSFER_OFFER",
    [CLIENT_TRANSFER]       = "CLIENT_TRANSFER",
    [CLIENT_DONE]           = "CLIENT_DONE"
};
// clang-format on

#define CLIENTSTATE_CHANGE(cur, next) (void)(cur = next)

extern struct config g_config;

static sigjmp_buf jmpenv;
static atomic_bool jmpenv_lock;

ATTRIBUTE_NORETURN static void alrm_handler(int sig ATTRIBUTE_UNUSED) {
  siglongjmp(jmpenv, 1);
}

static inline const char *get_clientstate_name(ZT_CLIENT_STATE state) {
  if (likely(state >= CLIENT_NONE && state <= CLIENT_DONE))
    return clientstate_names[state];
  else
    return "Unknown";
}

static err_t client_resolve_host_timeout(zt_client_connection_t *conn,
                                         struct zt_addrinfo **ai_list,
                                         timediff_t timeout_msec) {
  err_t ret = ERR_SUCCESS;
  int status, af, preferred_family = -1;
  struct zt_addrinfo *preferred = NULL, *preferred_tail = NULL;
  struct zt_addrinfo *unpreferred = NULL, *unpreferred_tail = NULL;
  struct zt_addrinfo *ai_cur;
  struct addrinfo hints, *res = NULL, *cur;
  size_t saddr_len;
  bool use_ipv6 = false;
  char ipstr[INET6_ADDRSTRLEN];

#if 1 // USE_SIGACT_TIMEOUT
  struct sigaction sigact, sigact_old;
  volatile bool have_old_sigact = false;
  volatile long timeout;
  volatile unsigned int prev_alarm = 0;
#endif

  ASSERT(conn);
  ASSERT(conn->state == CLIENT_CONN_INIT);
  ASSERT(timeout_msec > 0);

#if 1 // USE_SIGACT_TIMEOUT
  if (atomic_flag_test_and_set(&jmpenv_lock))
    return ERR_ALREADY;

  if (sigsetjmp(jmpenv, 1)) {
    /* This is coming from a siglongjmp() after an alarm signal */
    log_error(NULL, "host resolution timed out");
    ret = ERR_TIMEOUT;
    goto out;
  } else {
    sigaction(SIGALRM, NULL, &sigact);
    sigact_old = sigact;    /* store the old action */
    have_old_sigact = true; /* we have a copy */
    sigact.sa_handler = alrm_handler;
#ifdef SA_RESTART
    sigact.sa_flags &= ~SA_RESTART;
#endif
    /* Set the new action */
    sigaction(SIGALRM, &sigact, NULL);

    /**
     * This will cause a SIGALRM signal to be sent after `timeout_msec`
     * in seconds (rounded up) which will cause the system call to abort
     */
    prev_alarm = alarm(zt_sltoui((timeout_msec + 999) / 1000));
  }
#endif

#ifdef USE_IPV6
  /* Check if the system has IPv6 enabled and the config allows it */
  if (!g_config.flag_ipv4_only) {
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s != -1) {
      use_ipv6 = true;
      close(s);
    }
  }
#endif

  af = zt_choose_ip_family(!g_config.flag_ipv6_only, use_ipv6);
  if (af < 0) {
    log_error(NULL, "could not choose a suitable address family");
    ret = ERR_BAD_ARGS;
    goto out;
  }

  if (af == AF_UNSPEC)
    preferred_family = g_config.preferred_family == '4' ? AF_INET : AF_INET6;

  zt_memset(&hints, 0, sizeof(hints));
  hints.ai_family = af;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICSERV;

  for (int ntries = 0; ntries < CLIENT_RESOLVE_RETRIES; ntries++) {
    status = getaddrinfo(conn->hostname, conn->port, &hints, &res);

    if (status == 0 || status != EAI_AGAIN)
      break;

    if (ntries < CLIENT_RESOLVE_RETRIES - 1)
      sleep(1);
  }

  if (status) {
    const char *errstr = (status == EAI_SYSTEM) ? (const char *)strerror(errno)
                                                : gai_strerror(status);
    log_error(NULL, "getaddrinfo: failed for %s (%s)", conn->hostname, errstr);
    ret = ERR_NORESOLVE;
    goto out;
  }

  /* Build the list of zt_addrinfo while respecting the preferred_family if the
   * address family is AF_UNSPEC  */
  *ai_list = NULL;
  for (cur = res; cur != NULL; cur = cur->ai_next) {
    size_t cname_len = cur->ai_canonname ? strlen(cur->ai_canonname) + 1 : 0;

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

    /* Allocate a single block for all members of zt_addrinfo */
    ai_cur = zt_malloc(sizeof(struct zt_addrinfo) + cname_len + saddr_len);
    if (!ai_cur) {
      ret = ERR_MEM_FAIL;
      goto out;
    }

    /* Copy each member */
    ai_cur->ai_flags = cur->ai_flags;
    ai_cur->ai_family = cur->ai_family;
    ai_cur->ai_socktype = cur->ai_socktype;
    ai_cur->ai_protocol = cur->ai_protocol;
    ai_cur->ai_addrlen = cur->ai_addrlen;
    ai_cur->ai_canonname = NULL;
    ai_cur->ai_addr = NULL;
    ai_cur->ai_next = NULL;
    ai_cur->total_size = sizeof(struct zt_addrinfo) + cname_len + saddr_len;

    ai_cur->ai_addr = (void *)((char *)ai_cur + sizeof(struct zt_addrinfo));
    zt_memcpy(ai_cur->ai_addr, cur->ai_addr, saddr_len);

    if (cname_len) {
      ai_cur->ai_canonname = (void *)((char *)ai_cur->ai_addr + saddr_len);
      zt_memcpy(ai_cur->ai_canonname, cur->ai_canonname, cname_len);
    }

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

    log_debug(NULL, "Resolved %s to %s", conn->hostname,
              inet_ntop(cur->ai_family, cur->ai_addr, ipstr, sizeof(ipstr)));
  }

  /* Merge the lists based on the preferred family (if any) */
  if (preferred) {
    preferred_tail->ai_next = unpreferred;
    *ai_list = preferred;
  } else {
    *ai_list = unpreferred;
  }

out:
#if 1 // USE_SIGACT_TIMEOUT
  /* Deactivate a possibly active timeout before uninstalling the handler */
  if (!prev_alarm)
    alarm(0);

  /* Restore the old struct */
  if (have_old_sigact)
    sigaction(SIGALRM, &sigact_old, NULL);

  atomic_flag_clear(&jmpenv_lock);

  /**
   * Restore the previous alarm (if any) to when it was replaced minus the
   * time elapsed; if the previous timeout should have gone off, handle it
   * here
   */
  if (prev_alarm) {
    timediff_t elapsed_sec =
        zt_timediff_msec(zt_time_now(), conn->created_at) / 1000;

    unsigned long alarm_runout = (unsigned long)(prev_alarm - elapsed_sec);

    /**
     * Check if the previous alarm has possibly already expired by checking for
     * an unsigned wraparound indicating a negative value
     */
    if (!alarm_runout ||
        (alarm_runout >= 0x80000000 && prev_alarm <= 0x80000000)) {
      /* Set off the alarm; note that alarm(0) would switch it
       * off instead of firing it now! */
      alarm(1);
      ret = ERR_TIMEOUT; /* previous timeout ran out whilst resolving host */
    } else {
      alarm((unsigned int)alarm_runout); /* set the previous alarm back */
    }
  }
#endif

  /* If there was an error, free the zt_addrinfo list */
  if (ret) {
    zt_addrinfo_free(*ai_list);
    *ai_list = NULL;
  }
  freeaddrinfo(res);
  return ret;
}

static err_t client_tcp_conn0(zt_client_connection_t *conn,
                              struct zt_addrinfo *ai_list) {
  err_t ret = ERR_SUCCESS;
  struct zt_addrinfo *ai_cur, *ai_estab = NULL;
  int sockfd, on;

  ASSERT(conn);
  ASSERT(conn->state == CLIENT_CONN_INIT);
  ASSERT(ai_list);

  for (ai_cur = ai_list; ai_cur; ai_cur = ai_cur->ai_next) {
    if ((sockfd = socket(ai_cur->ai_family, ai_cur->ai_socktype | SOCK_CLOEXEC,
                         ai_cur->ai_protocol))) {
      log_error(NULL, "socket: failed (%s)", strerror(errno));
      continue;
    }

    if (SOCK_CLOEXEC == 0) {
      int flags = fcntl(sockfd, F_GETFD);
      if (flags < 0) {
        log_error(NULL, "fcntl: failed to get flags (%s)", strerror(errno));
        flags = 0;
      }
      flags |= FD_CLOEXEC;
      if (fcntl(sockfd, F_SETFD, flags) == -1)
        log_error(NULL, "fcntl: failed to set O_CLOEXEC (%s)", strerror(errno));
    }

    /* Try to enable TCP_NODELAY */
    if (conn->fl_tcp_nodelay) {
#ifdef TCP_NODELAY
      on = 1;
      if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on,
                     sizeof(on)) == -1) {
        log_error(NULL, "setsockopt: failed to set TCP_NODELAY (%s)",
                  strerror(errno));
        conn->fl_tcp_nodelay = false;
      }
#else
      log_error(NULL,
                "TCP_NODELAY was requested but not supported by this build");
      conn->fl_tcp_nodelay = false;
#endif
    }

    /* Try to enable TCP_FASTOPEN */
    if (conn->fl_tcp_fastopen) {
#if defined(TCP_FASTOPEN_CONNECT) /* Linux >= 4.11 */
      on = 1;
      if (setsockopt(conn->sockfd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                     (void *)&on, sizeof(on)) == -1) {
        log_error(NULL, "setsockopt: failed to set TCP_FASTOPEN_CONNECT (%s)",
                  strerror(errno));
        conn->fl_tcp_fastopen = false;
      }
#elif !defined(MSG_FASTOPEN) /* old Linux */
      log_error(NULL,
                "TCP_FASTOPEN was requested but not supported by this build");
      conn->fl_tcp_fastopen = false;
#endif
    }

    /* Try to enable TCP_KEEPALIVE for live reads */
    if (conn->fl_live_read) {
      on = 1;
      if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
                     sizeof(on)) == -1) {
        log_error(NULL, "setsockopt: failed to set SO_KEEPALIVE (%s)",
                  strerror(errno));
      }
    }

    struct timeval tval = {.tv_sec = conn->send_timeout / 1000,
                           .tv_usec = (conn->send_timeout % 1000) * 1000};
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tval,
                   sizeof(tval)) == -1) {
      log_error(NULL, "setsockopt: failed to set SO_SNDTIMEO (%s)",
                strerror(errno));
      close(sockfd);
      continue;
    }

    struct timeval tval = {.tv_sec = conn->recv_timeout / 1000,
                           .tv_usec = (conn->recv_timeout % 1000) * 1000};
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tval,
                   sizeof(tval)) == -1) {
      log_error(NULL, "setsockopt: failed to set SO_RCVTIMEO (%s)",
                strerror(errno));
      close(sockfd);
      continue;
    }

    /* If nothing failed we have found a valid candidate */
    break;
  }

  if (ai_cur) {
    ai_estab = zt_malloc(ai_cur->total_size);
    if (!ai_estab)
      ret = ERR_MEM_FAIL;
    zt_memcpy(ai_estab, ai_cur, ai_cur->total_size);
    ai_estab->ai_next = NULL;
    conn->sockfd = sockfd;
    conn->ai_estab = ai_estab;
  } else {
    log_error(NULL, "could not create a suitable socket for any address");
    ret = ERR_INTERNAL;
  }

exit:
  if (ret) {
    conn->sockfd = -1;
    close(sockfd);
  }
  zt_addrinfo_free(ai_list);
  return ret;
}

static err_t client_tcp_conn1(zt_client_connection_t *conn) {
  int rv, flags;
  int sockfd;
  struct zt_addrinfo *ai_estab;

  ASSERT(conn);
  ASSERT(conn->state == CLIENT_CONN_INIT);
  ASSERT(conn->ai_estab);
  ASSERT(conn->sockfd >= 0);

  /**
   * Make this connect non-blocking. We don't need a connection immediately
   * and instead of waiting can use the time for the handshake setup process
   */
  sockfd = conn->sockfd;
  conn->sock_flags = flags = fcntl(sockfd, F_GETFL, 0);
  fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

  ai_estab = conn->ai_estab;

#if defined(MSG_FASTOPEN) && !defined(TCP_FASTOPEN_CONNECT)
  if (conn->fl_tcp_fastopen) {
    conn->first_send = true;
    /**
     * Do nothing -- we must send the TFO cookie/cookie request using the
     * sendto() syscall with the `MSG_FASTOPEN` flag as the first send of
     * this connection
     */
    rv = 0;
#elif defined(TCP_FASTOPEN_CONNECT)
  if (conn->fl_tcp_fastopen) {
    rv = connect(sockfd, ai_estab->ai_addr, ai_estab->ai_addrlen);
    conn->first_send = false;
#else
  if (0) {
#endif
  } else {
    rv = connect(sockfd, ai_estab->ai_addr, ai_estab->ai_addrlen);
    conn->first_send = false;
  }

  // clang-format off
  if (rv == -1 &&
    errno != EAGAIN &&
    errno != EWOULDBLOCK &&
    errno != EINPROGRESS) {
    // clang-format on
    log_error(NULL, "connect: failed (%s)", strerror(errno));
    close(conn->sockfd);
    return ERR_TCP_CONNECT;
  }

#ifdef DEBUG
  char address[INET6_ADDRSTRLEN + 6];
  getnameinfo(ai_estab->ai_addr, ai_estab->ai_addrlen, address,
              INET6_ADDRSTRLEN, &address[INET6_ADDRSTRLEN], 6,
              NI_NUMERICHOST | NI_NUMERICSERV);
  log_debug(NULL, "connected to %s:%d", address, &address[INET6_ADDRSTRLEN]);
#endif

  /**
   * We are done for now, but it is important to verify the connection
   * before performing a read/write and restore the file status flags then
   */
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
static err_t client_send(zt_client_connection_t *conn) {
  err_t ret;
  size_t len, tosend, taglen;
  uint8_t *p, *datap;
  bool is_encrypted;

  ASSERT(conn);
  ASSERT(conn->state > CLIENT_CONN_INIT && conn->state < CLIENT_DONE);
  ASSERT(conn->msgbuf);

  if (MSG_DATA_LEN(conn->msgbuf) > ZT_MSG_MAX_RW_SIZE) {
    log_error(NULL, "message data too large (%zu bytes)",
              MSG_DATA_LEN(conn->msgbuf));
    return ERR_REQUEST_TOO_LARGE;
  }

  is_encrypted = !(MSG_TYPE(conn->msgbuf) & (MSG_HANDSHAKE | MSG_AUTH_RETRY));

  p = MSG_DATA_PTR(conn->msgbuf);
  len = MSG_DATA_LEN(conn->msgbuf);
  p[len++] = MSG_END_BYTE; /* end of data */

  if (conn->state == CLIENT_TRANSFER) {
    if (g_config.flag_length_obfuscation) {
      size_t padding;

      taglen = vcry_get_aead_tag_len();

      padding = (len - 1) & (g_config.padding_factor - 1);
      zt_memset(p + len, 0x00, padding); // FIX: possible side-channel?
      len += padding;

      MSG_SET_FLAGS(conn->msgbuf, MSG_FLAGS(conn->msgbuf) | MSG_FL_PADDING);
    } else if (g_config.flag_lz4_compression) {
      const char *rptr = (const char *)p;
      char *wptr = (char *)(MSG_XBUF_PTR(conn->msgbuf) + ZT_MSG_HEADER_SIZE);

      len = LZ4_compress_default(rptr, wptr, len, ZT_MSG_XBUF_SIZE);
      if (len == 0) {
        log_error(NULL, "LZ4_compress_default(): failed to compress %zu bytes",
                  len);
        return ERR_INTERNAL;
      }

      MSG_SET_LEN(conn->msgbuf, len); /*update length in header before copying*/
      MSG_SET_FLAGS(conn->msgbuf, MSG_FLAGS(conn->msgbuf) | MSG_FL_COMPRESSION);
      zt_memcpy(MSG_XBUF_PTR(conn->msgbuf), MSG_RAW_PTR(conn->msgbuf),
                ZT_MSG_HEADER_SIZE);
    }
  }
  MSG_SET_LEN(conn->msgbuf, len); /* update length in header */

  p = MSG_FLAGS(conn->msgbuf) & MSG_FL_COMPRESSION ? MSG_RAW_PTR(conn->msgbuf)
                                                   : MSG_XBUF_PTR(conn->msgbuf);
  datap = p + ZT_MSG_HEADER_SIZE;
  if (is_encrypted) {
    if ((ret = vcry_aead_encrypt(datap, len, p, ZT_MSG_HEADER_SIZE, datap,
                                 &tosend)) != ERR_SUCCESS) {
      log_error(NULL, "encryption failed");
      return ret;
    }
  } else {
    tosend = len;
  }
  tosend += ZT_MSG_HEADER_SIZE; /* we're sending header+payload */

  if (zt_client_tcp_send(conn, p, tosend) != 0) {
    log_error(NULL, "failed to send %zu bytes to peer (%s)", tosend,
              strerror(errno));
    return ERR_TCP_SEND;
  }

  // MSG_SET_LEN(conn->msgbuf, 0);

  return ERR_SUCCESS;
}

#define msg_type_is_expected(msgtype, mask)                                    \
  (msgtype == MSG_ANY || (msgtype & mask))

/**
 * @param[in] conn The client connection context.
 * @param[in] expected_types A bitmask of expected message types.
 * @return An `err_t` status code.
 *
 * Receive a message from the peer and store it in `conn->msgbuf`.
 *
 * The type of the message (resulting `conn->msgbuf->type`) must match
 * one of the types set in the @p expected_types bitmask.
 * If `expected_types=MSG_ANY`, any valid message type will be accepted.
 *
 * The amount of payload data to be read is indicated by a fixed-size header
 * prefix. If a failure occurs before all of this payload data is received
 * (either because of a timeout or other error), the function returns an error
 * code and sets the message length to 0.
 *
 * Encrypted payload data is decrypted in-place in `conn->msgbuf->data[]`.
 */
static err_t client_recv(zt_client_connection_t *conn,
                         zt_msg_type_t expected_types) {
  err_t ret = ERR_SUCCESS;
  ssize_t nread;
  size_t datalen, taglen;
  uint8_t *rawptr, *dataptr;
  bool is_encrypted;

  ASSERT(conn);
  ASSERT(conn->state > CLIENT_CONN_INIT && conn->state <= CLIENT_DONE);
  ASSERT(conn->msgbuf);

  rawptr = MSG_RAW_PTR(conn->msgbuf);
  dataptr = MSG_DATA_PTR(conn->msgbuf);

  /* Read the message header */
  nread = zt_client_tcp_recv(conn, rawptr, ZT_MSG_HEADER_SIZE, NULL);
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
    log_error(NULL, "recieved malformed header (invalid type)");
    ret = ERR_INVALID_DATUM;
    goto out;
  }
  if (!msg_type_is_expected(MSG_TYPE(conn->msgbuf), expected_types)) {
    log_error(NULL, "bad message (expected %u)", MSG_TYPE(conn->msgbuf),
              expected_types);
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  is_encrypted = !(MSG_TYPE(conn->msgbuf) & (MSG_HANDSHAKE | MSG_AUTH_RETRY));

  taglen = is_encrypted ? vcry_get_aead_tag_len() : 0;
  datalen = MSG_DATA_LEN(conn->msgbuf) + taglen;

  /* Read message payload */
  nread = zt_client_tcp_recv(conn, dataptr, datalen, NULL);
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

  /* Decrypt the payload if required */
  if (is_encrypted) {
    if ((ret = vcry_aead_decrypt(dataptr, datalen, rawptr, ZT_MSG_HEADER_SIZE,
                                 dataptr, &nread)) != ERR_SUCCESS) {
      log_error(NULL, "decryption failed");
      goto out;
    }
  }

out:
  if (unlikely(ret))
    MSG_SET_LEN(conn->msgbuf, 0);
  else
    MSG_SET_LEN(conn->msgbuf, nread);

  return ret;
}

err_t zt_client_conn_alloc(zt_client_connection_t **conn) {
  size_t alloc_size;

  if (!conn)
    return ERR_NULL_PTR;

  alloc_size = sizeof(zt_client_connection_t) + sizeof(zt_msg_t);
  if (g_config.flag_lz4_compression)
    alloc_size += ZT_MSG_XBUF_SIZE;

  if (!(*conn = zt_calloc(1, alloc_size)))
    return ERR_MEM_FAIL;

  (*conn)->msgbuf =
      (zt_msg_t *)((char *)(*conn) + sizeof(zt_client_connection_t));
  (*conn)->msgbuf->_xbuf =
      (uint8_t *)((char *)(*conn) + sizeof(zt_client_connection_t) +
                  sizeof(zt_msg_t));

  (*conn)->sockfd = -1;

  return ERR_SUCCESS;
}

void zt_client_conn_dealloc(zt_client_connection_t *conn) {
  if (!conn)
    return;

  zt_free(conn);
}

err_t zt_client_run(zt_client_connection_t *conn, void *args ATTRIBUTE_UNUSED,
                    bool *done) {
  err_t ret = ERR_SUCCESS;
  struct passwd *master_pass;
  int vcry_algs[6];
  ciphersuite_t ciphersuite;
  zt_fio_t fileptr;
  zt_fileinfo_t fileinfo;
  char port[6];

  if (!conn || !done)
    return ERR_NULL_PTR;

  if (zt_get_hostid(&conn->authid_mine) != 0)
    return ERR_INTERNAL;

  // clang-format off
  if ((ciphersuite = zt_cipher_suite_info_from_repr(
           g_config.ciphersuite,
           &vcry_algs[0], &vcry_algs[1], &vcry_algs[2],
           &vcry_algs[3], &vcry_algs[4], &vcry_algs[5])) == 0) {
    return ERR_INVALID;
  }
  // clang-format on

  conn->hostname = g_config.hostname;

  if (conn->fl_explicit_port) {
    snprintf(port, sizeof(port), "%u", g_config.port);
    conn->port = port;
  } else {
    conn->port = ZT_DEFAULT_LISTEN_PORT;
  }

  conn->connect_timeout = g_config.connect_timeout > 0
                              ? g_config.connect_timeout
                              : ZT_CLIENT_TIMEOUT_CONNECT_DEFAULT;
  conn->recv_timeout = g_config.recv_timeout > 0
                           ? g_config.recv_timeout
                           : ZT_CLIENT_TIMEOUT_RECV_DEFAULT;
  conn->send_timeout = g_config.send_timeout > 0
                           ? g_config.send_timeout
                           : ZT_CLIENT_TIMEOUT_SEND_DEFAULT;

  conn->state = CLIENT_CONN_INIT;

  while (1) {
    switch (conn->state) {
    case CLIENT_CONN_INIT: {
      struct zt_addrinfo *ai_list = NULL;

      /* The timeout is guaranteed to be positive so we don't infinitely wait on
       * a DNS resolution */
      ret = client_resolve_host_timeout(conn, &ai_list, conn->connect_timeout);
      if (ret != ERR_SUCCESS)
        return ret;

      if ((ret = client_tcp_conn0(conn, ai_list)) != ERR_SUCCESS)
        goto cleanup1;

      if ((ret = client_tcp_conn1(conn)) != ERR_SUCCESS)
        goto cleanup2;

      CLIENTSTATE_CHANGE(conn->state, CLIENT_AUTH_INIT);
      ATTRIBUTE_FALLTHROUGH;
    }

    case CLIENT_AUTH_INIT: {
      uint8_t *sndbuf;
      size_t sndlen, len;
      passwd_id_t passwd_id;

      static int retrycount = 1; /* number of entries into this state */
      if (retrycount > MAX_AUTH_RETRY_COUNT) {
        log_error(NULL, "too many handshake failures -- aborting!");
        ret = ERR_HSHAKE_ABORTED;
        goto cleanup2;
      }
      retrycount++;

      if (conn->renegotiation) {
        /* We can only get here when auth_type=KAPPA1 */
        passwd_id =
            zt_auth_passwd_load(g_config.passwddb_file, g_config.hostname,
                                conn->renegotiation_passwd, &master_pass);
      } else {
        passwd_id =
            zt_auth_passwd_new(g_config.passwddb_file, g_config.auth_type,
                               conn->hostname, &master_pass);
      }
      if (passwd_id < 0) {
        ret = ERR_INTERNAL;
        log_error(NULL, "could not load master password for hostname '%s'",
                  conn->hostname);
        goto cleanup2;
      }

      if ((ret = vcry_module_init()) != ERR_SUCCESS) {
        zt_auth_passwd_free(master_pass, NULL);
        goto cleanup2;
      }

      vcry_set_role_initiator();

      if ((ret = vcry_set_authpass(master_pass->pw, master_pass->pwlen)) !=
          ERR_SUCCESS) {
        log_error(NULL, "vcry_set_authpass() : %s", zt_strerror(ret));
        zt_auth_passwd_free(master_pass, NULL);
        goto cleanup2;
      }
      zt_auth_passwd_free(master_pass, NULL);

      // clang-format off
      if ((ret = vcry_set_crypto_params(
               vcry_algs[0], vcry_algs[1], vcry_algs[2],
               vcry_algs[3], vcry_algs[4], vcry_algs[5])) != ERR_SUCCESS) {
        log_error(NULL, "vcry_set_crypto_params() : %s", zt_strerror(ret));
        goto cleanup2;
      }
      // clang-format on

      if ((ret = vcry_handshake_initiate(&sndbuf, &sndlen)) != ERR_SUCCESS) {
        log_error(NULL, "vcry_handshake_initiate() : %s", zt_strerror(ret));
        goto cleanup2;
      }

      /* Check if the connect() was successful and we have a writable socket */
      if (!zt_tcp_io_waitfor_write(conn->sockfd, conn->connect_timeout)) {
        zt_free(sndbuf);
        ret = ERR_TCP_CONNECT;
        goto cleanup2;
      }

      zt_memcpy(MSG_DATA_PTR(conn->msgbuf), conn->authid_mine.bytes,
                AUTHID_BYTES_LEN);
      len = AUTHID_BYTES_LEN;

      zt_memcpy(MSG_DATA_PTR(conn->msgbuf) + len, PTRV(&passwd_id),
                sizeof(passwd_id_t));
      len += sizeof(passwd_id_t);

      // TODO: we don't need to send this again with renegotiation messages
      zt_memcpy(MSG_DATA_PTR(conn->msgbuf) + len, PTRV(&ciphersuite),
                sizeof(ciphersuite_t));
      len += sizeof(ciphersuite_t);

      zt_memcpy(MSG_DATA_PTR(conn->msgbuf) + len, sndbuf, sndlen);
      len += sndlen;

      zt_free(sndbuf);

      MSG_SET_LEN(conn->msgbuf, len);
      MSG_SET_TYPE(conn->msgbuf, MSG_HANDSHAKE);

      if ((ret = client_send(conn)) != ERR_SUCCESS)
        goto cleanup2;

      CLIENTSTATE_CHANGE(conn->state, CLIENT_AUTH_COMPLETE);
      ATTRIBUTE_FALLTHROUGH;
    }

    case CLIENT_AUTH_COMPLETE: {
      uint8_t *rcvbuf, *sndbuf;
      size_t rcvlen, sndlen;

      zt_msg_type_t expectmask = MSG_AUTH_RETRY | MSG_HANDSHAKE;
      if ((ret = client_recv(conn, expectmask)) != ERR_SUCCESS)
        goto cleanup2;

      rcvlen = MSG_DATA_LEN(conn->msgbuf);
      rcvbuf = MSG_DATA_PTR(conn->msgbuf);

      switch (MSG_TYPE(conn->msgbuf)) {
      case MSG_AUTH_RETRY: {
        /**
         * The peer wants to retry authentication and has sent a new password Id
         * (note that this only happens in KAPPA1 auth mode).
         *
         * 1. Warn the user about a possible MITM and ask whether to continue.
         *
         * 2. Check if this password Id is available in the passwddb, and offer
         *    a new Id (not necessarily the same as the one sent by the peer).
         */
        if (g_config.auth_type != KAPPA_AUTHTYPE_1) {
          log_error(NULL, "peer sent MSG_AUTH_RETRY but auth_type!=KAPPA1");
          ret = ERR_BAD_CONTROL_FLOW;
          goto cleanup2;
        }

        if (!tty_get_answer_is_yes(g_CLIPrompts[OnBadPasswdIdentifier])) {
          ret = ERR_HSHAKE_ABORTED;
          goto cleanup2;
        }

        if (rcvlen < sizeof(passwd_id_t)) {
          ret = ERR_INVALID_DATUM;
          goto cleanup2;
        }

        conn->renegotiation_passwd = ((passwd_id_t *)rcvbuf)[0];
        conn->renegotiation = true;

        /* handshake will be restarted */
        vcry_module_release();

        CLIENTSTATE_CHANGE(conn->state, CLIENT_AUTH_INIT);
        break;
      } /* case MSG_AUTH_RETRY */

      case MSG_HANDSHAKE: {
        /* We should have recieved the expected handshake response */
        if (rcvlen < AUTHID_BYTES_LEN + VCRY_VERIFY_MSG_LEN) {
          return ERR_INVALID_DATUM;
          goto cleanup2;
        }

        /* copy peer AuthId */
        zt_memcpy(conn->authid_peer.bytes, rcvbuf, AUTHID_BYTES_LEN);

        rcvbuf += AUTHID_BYTES_LEN;
        rcvlen -= AUTHID_BYTES_LEN;

        /* process handshake response */
        if ((ret = vcry_handshake_complete(
                 rcvbuf, rcvlen - VCRY_VERIFY_MSG_LEN)) != ERR_SUCCESS) {
          log_error(NULL, "vcry_handshake_complete() : %s", zt_strerror(ret));
          goto cleanup2;
        }

        if ((ret = vcry_derive_session_key()) != ERR_SUCCESS)
          goto cleanup2;

        /* create our verify-initiation message */
        if ((ret = vcry_initiator_verify_initiate(
                 &sndbuf, &sndlen, conn->authid_mine.bytes,
                 conn->authid_peer.bytes)) != ERR_SUCCESS) {
          log_error(NULL, "vcry_initiator_verify_initiate() : %s",
                    zt_strerror(ret));
          goto cleanup2;
        }

        MSG_MAKE(conn->msgbuf, MSG_HANDSHAKE, sndbuf, sndlen, 0);
        zt_free(sndbuf);

        /* Process the responder's verify-initiation message */
        ret = vcry_initiator_verify_complete(
            rcvbuf + (ptrdiff_t)(rcvlen - VCRY_VERIFY_MSG_LEN),
            conn->authid_mine.bytes, conn->authid_peer.bytes);
        switch (ret) {
        case ERR_SUCCESS:
          break; /* successful */
        case ERR_AUTH_FAIL:
          goto retryhandshake;
        default:
          log_error(NULL, "vcry_initiator_verify_complete() : %s",
                    zt_strerror(ret));
          goto cleanup2;
        }

        /* Send our verify-initiation message to the peer */
        if ((ret = client_send(conn)) != ERR_SUCCESS)
          goto cleanup2;

        CLIENTSTATE_CHANGE(conn->state, CLIENT_OFFER);
      } /* case MSG_HANDSHAKE */
      }
      break;

    retryhandshake:
      /**
       * We are here because although the handshake messages were correctly
       * structured, there was an authentication failure, likely due to
       * incorrect credentials. Inform the user about a possible MITM and ask
       * whether to continue.
       * If the user chooses to continue, we will restart the handshake from the
       * initiation phase.
       */

      if (!tty_get_answer_is_yes(
              g_CLIPrompts[OnPossibleIncorrectPasswdAttempt])) {
        ret = ERR_HSHAKE_ABORTED;
        goto cleanup2;
      }

      /* handshake will be restarted */
      vcry_module_release();

      CLIENTSTATE_CHANGE(conn->state, CLIENT_AUTH_INIT);
      break;
    }

    case CLIENT_OFFER: {
      /**
       * Open the and lock the file here, so that its size remains fixed until
       * the entire file is sent
       */
      if ((ret = zt_fio_open(&fileptr, g_config.filename, FIO_RDONLY)) !=
          ERR_SUCCESS) {
        goto cleanup2;
      }

      if ((ret = zt_fio_fileinfo(&fileptr, &fileinfo)) != ERR_SUCCESS) {
        zt_fio_close(&fileptr);
        goto cleanup2;
      }

      fileinfo.size = hton64(fileinfo.size);
      fileinfo.reserved = hton32(fileinfo.reserved);
      MSG_MAKE(conn->msgbuf, MSG_METADATA, (void *)&fileinfo,
               sizeof(zt_fileinfo_t), 0);
      memzero(&fileinfo, sizeof(zt_fileinfo_t));

      if ((ret = client_send(conn)) != ERR_SUCCESS) {
        zt_fio_close(&fileptr);
        goto cleanup2;
      }

      CLIENTSTATE_CHANGE(conn->state, CLIENT_TRANSFER);
      ATTRIBUTE_FALLTHROUGH;
    }

    case CLIENT_TRANSFER: {
      size_t nread;
      err_t rv;

      if (zt_progressbar_init() != 0)
        log_error(NULL, "failed to create progress bar");

      zt_progressbar_begin(g_config.hostname, fileinfo.name, fileinfo.size);

      MSG_SET_TYPE(conn->msgbuf, MSG_FILEDATA);
      while (1) {
        rv = zt_fio_read(&fileptr, MSG_DATA_PTR(conn->msgbuf),
                         ZT_MSG_MAX_RW_SIZE, &nread);
        if (rv != ERR_SUCCESS)
          break;

        MSG_SET_LEN(conn->msgbuf, nread);

        if ((ret = client_send(conn)) != ERR_SUCCESS) {
          zt_fio_close(&fileptr);
          zt_progressbar_complete();
          zt_progressbar_destroy();
          goto cleanup2;
        }
        zt_progressbar_update(nread);
      }
      zt_fio_close(&fileptr);
      zt_progressbar_complete();
      zt_progressbar_destroy();

      if (rv != ERR_EOF) {
        ret = rv;
        goto cleanup2;
      }

      CLIENTSTATE_CHANGE(conn->state, CLIENT_DONE);
      ATTRIBUTE_FALLTHROUGH;
    }

    case CLIENT_DONE: {
      MSG_MAKE(conn->msgbuf, MSG_DONE, PTR8(DONE_MSG_UTF8),
               sizeof(DONE_MSG_UTF8), 0);

      if ((ret = client_send(conn)) != ERR_SUCCESS)
        goto cleanup2;

      CLIENTSTATE_CHANGE(conn->state, CLIENT_NONE);
      *done = true;
      goto cleanup2;
    }

    default: {
      log_error(NULL, "bad client state - %s",
                get_clientstate_name(conn->state));
      ret = ERR_INVALID;
      goto cleanup2;
    }
    } /* switch(conn->state) */
  } /* while(1) */

cleanup2:
  vcry_module_release();

  shutdown(conn->sockfd, SHUT_RDWR);
  close(conn->sockfd);

cleanup1:
  zt_addrinfo_free(conn->ai_estab);

  return ret;
}

err_t zt_client_enable_tcp_fastopen(zt_client_connection_t *conn, bool enable) {
  if (!conn)
    return ERR_NULL_PTR;

  if (conn->state != CLIENT_NONE)
    return ERR_INVALID;

  conn->fl_tcp_fastopen = enable;
}

err_t zt_client_enable_explicit_port(zt_client_connection_t *conn,
                                     bool enable) {
  if (!conn)
    return ERR_NULL_PTR;

  if (conn->state != CLIENT_NONE)
    return ERR_INVALID;

  conn->fl_explicit_port = enable;

  return ERR_SUCCESS;
}

err_t zt_client_enable_tcp_nodelay(zt_client_connection_t *conn, bool enable) {
  if (!conn)
    return ERR_NULL_PTR;

  if (conn->state != CLIENT_NONE)
    return ERR_INVALID;

  conn->fl_tcp_nodelay = enable;

  return ERR_SUCCESS;
}

err_t zt_client_enable_live_read(zt_client_connection_t *conn, bool enable) {
  if (!conn)
    return ERR_NULL_PTR;

  if (conn->state != CLIENT_NONE)
    return ERR_INVALID;

  conn->fl_live_read = enable;

  return ERR_SUCCESS;
}
