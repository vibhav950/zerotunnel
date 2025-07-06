#include "client.h"
#include "auth.h"
#include "common/defines.h"
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

#define CLIENTSTATE_CHANGE(cur, next) (void)(cur = next)

static const char clientstate_names[][20] = {
    [CLIENT_NONE] = "CLIENT_NONE",
    [CLIENT_CONN_INIT] = "CLIENT_CONN_INIT",
    [CLIENT_AUTH_PING] = "CLIENT_AUTH_PING",
    [CLIENT_AUTH_PONG] = "CLIENT_AUTH_PONG",
    [CLIENT_OFFER] = "CLIENT_TRANSFER_OFFER",
    [CLIENT_TRANSFER] = "CLIENT_TRANSFER",
    [CLIENT_DONE] = "CLIENT_DONE"};

static sigjmp_buf jmpenv;
static atomic_bool jmpenv_lock;

ATTRIBUTE_NORETURN static void alrm_handler(int sig ATTRIBUTE_UNUSED) {
  siglongjmp(jmpenv, 1);
}

static inline const char *get_clientstate_name(ZT_CLIENT_STATE state) {
  ASSERT(state >= CLIENT_NONE && state <= CLIENT_DONE);
  return clientstate_names[state];
}

static error_t zt_client_resolve_host_timeout(zt_client_connection_t *conn,
                                              struct zt_addrinfo **ai_list,
                                              timediff_t timeout_msec) {
  error_t ret = ERR_SUCCESS;
  struct zt_addrinfo *ai_head = NULL, *ai_tail = NULL, *ai_cur;
  struct addrinfo hints, *res = NULL, *p;
  size_t saddr_len;
  int status;
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

  if (!conn->hostname) {
    PRINTERROR("empty hostname string");
    return ERR_NULL_PTR;
  }

#if 1 // USE_SIGACT_TIMEOUT
  if (atomic_flag_test_and_set(&jmpenv_lock))
    return ERR_ALREADY;

  if (sigsetjmp(jmpenv, 1)) {
    /** This is coming from a siglongjmp() after an alarm signal */
    PRINTERROR("host resolution timed out");
    ret = ERR_TIMEOUT;
    goto cleanup;
  } else {
    sigaction(SIGALRM, NULL, &sigact);
    sigact_old = sigact;    /* store the old action */
    have_old_sigact = true; /* we have a copy */
    sigact.sa_handler = alrm_handler;
#ifdef SA_RESTART
    sigact.sa_flags &= ~SA_RESTART;
#endif
    /** Set the new action */
    sigaction(SIGALRM, &sigact, NULL);

    /**
     * This will cause a SIGALRM signal to be sent after `timeout_msec`
     * in seconds (rounded up) which will cause the system call to abort
     */
    prev_alarm = alarm(zt_sltoui((timeout_msec + 999) / 1000));
  }
#endif

#ifdef USE_IPV6
  /* Check if the system has IPv6 enabled */
  if (conn->fl_ipv6) {
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s != -1)
      close(s);
    else
      conn->fl_ipv6 = false;
  }
#endif

  zt_memset(&hints, 0, sizeof(hints));
  hints.ai_family = conn->fl_ipv6 ? AF_UNSPEC : AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  for (int ntries = 0; ntries < CLIENT_RESOLVE_RETRIES; ntries++) {
    status = getaddrinfo(conn->hostname, NULL, &hints, &res);

    if (status == 0 || status != EAI_AGAIN)
      break;

    if (ntries < CLIENT_RESOLVE_RETRIES - 1)
      sleep(1);
  }

  if (status) {
    const char *errstr = (status == EAI_SYSTEM) ? (const char *)strerror(errno)
                                                : gai_strerror(status);
    PRINTERROR("getaddrinfo: failed for %s (%s)", conn->hostname, errstr);
    return ERR_NORESOLVE;
  }

  for (p = res; p != NULL; p = p->ai_next) {
    size_t cname_len = p->ai_canonname ? strlen(p->ai_canonname) + 1 : 0;

    if (p->ai_family == AF_INET) {
      saddr_len = sizeof(struct sockaddr_in);
    }
#ifdef USE_IPV6
    else if (conn->fl_ipv6 && (p->ai_family == AF_INET6)) {
      saddr_len = sizeof(struct sockaddr_in6);
    }
#endif
    else {
      continue;
    }

    /* Ignore elements without required address info */
    if (!p->ai_addr || !(p->ai_addrlen > 0))
      continue;

    /* Ignore elements with bad address length */
    if ((size_t)p->ai_addrlen < saddr_len)
      continue;

    /* Allocate a single block for all members of zt_addrinfo */
    ai_cur = zt_malloc(sizeof(struct zt_addrinfo) + cname_len + saddr_len);
    if (!ai_cur) {
      ret = ERR_MEM_FAIL;
      goto cleanup;
    }

    /* Copy each member */
    ai_cur->ai_flags = p->ai_flags;
    ai_cur->ai_family = p->ai_family;
    ai_cur->ai_socktype = p->ai_socktype;
    ai_cur->ai_protocol = p->ai_protocol;
    ai_cur->ai_addrlen = p->ai_addrlen;
    ai_cur->ai_canonname = NULL;
    ai_cur->ai_addr = NULL;
    ai_cur->ai_next = NULL;
    ai_cur->total_size = sizeof(struct zt_addrinfo) + cname_len + saddr_len;

    ai_cur->ai_addr = (void *)((char *)ai_cur + sizeof(struct zt_addrinfo));
    zt_memcpy(ai_cur->ai_addr, p->ai_addr, saddr_len);

    if (cname_len) {
      ai_cur->ai_canonname = (void *)((char *)ai_cur->ai_addr + saddr_len);
      zt_memcpy(ai_cur->ai_canonname, p->ai_canonname, cname_len);
    }

    /** If the list is empty, set this node as the head */
    if (!ai_head)
      ai_head = ai_cur;

    /** Add this node to the tail of the list */
    if (ai_tail)
      ai_tail->ai_next = ai_cur;
    ai_tail = ai_cur;

    PRINTDEBUG("Resolved %s to %s", conn->hostname,
               inet_ntop(p->ai_family, p->ai_addr, ipstr, sizeof(ipstr)));
  }

  if (!ret)
    *ai_list = ai_head;
  else
    *ai_list = NULL;

cleanup:
#if 1 // USE_SIGACT_TIMEOUT
  /** Deactivate a possibly active timeout before uninstalling the handler */
  if (!prev_alarm)
    alarm(0);

  /** Restore the old struct */
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
  if (ret)
    zt_addrinfo_free(ai_head);
  freeaddrinfo(res);
  return ret;
}

static error_t zt_client_tcp_conn0(zt_client_connection_t *conn,
                                   struct zt_addrinfo *ai_list) {
  error_t ret = ERR_SUCCESS;
  struct zt_addrinfo *ai_cur, *ai_estab = NULL;
  int sockfd, on;

  ASSERT(conn);
  ASSERT(conn->state == CLIENT_CONN_INIT);
  ASSERT(ai_list);

  for (ai_cur = ai_list; ai_cur; ai_cur = ai_cur->ai_next) {
    int fail = 0;

    if ((sockfd = socket(ai_cur->ai_family, ai_cur->ai_socktype | SOCK_CLOEXEC,
                         ai_cur->ai_protocol))) {
      PRINTERROR("socket: failed (%s)", strerror(errno));
      continue;
    }

    if (SOCK_CLOEXEC == 0) {
      int flags = fcntl(sockfd, F_GETFD);
      if (flags < 0) {
        PRINTERROR("fcntl: failed to get flags (%s)", strerror(errno));
        flags = 0;
      }
      flags |= FD_CLOEXEC;
      if (fcntl(sockfd, F_SETFD, flags) == -1)
        PRINTERROR("fcntl: failed to set O_CLOEXEC (%s)", strerror(errno));
    }

    /** Try to enable TCP_NODELAY */
    if (conn->fl_tcp_nodelay) {
#ifdef TCP_NODELAY
      on = 1;
      if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("setsockopt: failed to set TCP_NODELAY (%s)",
                   strerror(errno));
        conn->fl_tcp_nodelay = false;
      }
#else
      PRINTERROR("TCP_NODELAY was requested but not supported by this build");
      conn->fl_tcp_nodelay = false;
#endif
    }

    /** Try to enable TCP_FASTOPEN */
    if (conn->fl_tcp_fastopen) {
#if defined(TCP_FASTOPEN_CONNECT) /* Linux >= 4.11 */
      on = 1;
      if (setsockopt(conn->sockfd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                     (void *)&on, sizeof(on)) == -1) {
        PRINTERROR("setsockopt: failed to set TCP_FASTOPEN_CONNECT (%s)",
                   strerror(errno));
        conn->fl_tcp_fastopen = false;
      }
#elif !defined(MSG_FASTOPEN) /* old Linux */
      PRINTERROR("TCP_FASTOPEN was requested but not supported by this build");
      conn->fl_tcp_fastopen = false;
#endif
    }

    /** We must have TCP keepalive enabled for live reads */
    if (conn->fl_live_read) {
      int fail = 0;

      on = 1;
      if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("setsockopt: failed to set SO_KEEPALIVE (%s)",
                   strerror(errno));
        fail = 1;
      }

      if (getsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("getsockopt: failed to get SO_KEEPALIVE (%s)",
                   strerror(errno));
        fail = 1;
      }

      if (fail || !on) {
        PRINTERROR("could not prepare socket for live read");
        close(sockfd);
        continue;
      }
    }

    if (conn->send_timeout > 0) {
      struct timeval tval = {.tv_sec = conn->send_timeout / 1000,
                             .tv_usec = (conn->send_timeout % 1000) * 1000};
      if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tval,
                     sizeof(tval)) == -1) {
        PRINTERROR("setsockopt: failed to set SO_SNDTIMEO (%s)",
                   strerror(errno));
        close(sockfd);
        continue;
      }
    }

    if (conn->recv_timeout > 0) {
      struct timeval tval = {.tv_sec = conn->recv_timeout / 1000,
                             .tv_usec = (conn->recv_timeout % 1000) * 1000};
      if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tval,
                     sizeof(tval)) == -1) {
        PRINTERROR("setsockopt: failed to set SO_RCVTIMEO (%s)",
                   strerror(errno));
        close(sockfd);
        continue;
      }
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
    PRINTERROR("could not create a suitable socket for any address");
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

static error_t zt_client_tcp_conn1(zt_client_connection_t *conn) {
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
     * do nothing; we must send the TFO cookie/cookie request using the sendto()
     * syscall with the `MSG_FASTOPEN` flag as the first send of this connection
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

  if (rv == -1 && errno != EAGAIN && errno != EINPROGRESS) {
    PRINTERROR("connect: failed (%s)", strerror(errno));
    close(conn->sockfd);
    return ERR_TCP_CONNECT;
  }

#ifdef DEBUG
  char address[INET6_ADDRSTRLEN + 6];
  getnameinfo(ai_estab->ai_addr, ai_estab->ai_addrlen, address,
              INET6_ADDRSTRLEN, &address[INET6_ADDRSTRLEN], 6,
              NI_NUMERICHOST | NI_NUMERICSERV);
  PRINTDEBUG("connected to %s:%d", address, &address[INET6_ADDRSTRLEN]);
#endif

  /**
   * We are done for now, but it is important to verify the connection
   * before performing a read/write and restore the file status flags then
   */
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
static error_t client_send(zt_client_connection_t *conn) {
  error_t ret;
  size_t len, tosend, taglen;
  uint8_t *rawptr;
  bool is_encrypted;

  ASSERT(conn);
  ASSERT(conn->state > CLIENT_CONN_INIT && conn->state < CLIENT_DONE);
  ASSERT(conn->msgbuf);

  if (zt_msg_data_len(conn->msgbuf) > ZT_MAX_TRANSFER_SIZE) {
    PRINTERROR("message data too large (%zu bytes)",
               zt_msg_data_len(conn->msgbuf));
    return ERR_REQUEST_TOO_LARGE;
  }

  is_encrypted = (zt_msg_type(conn->msgbuf) != MSG_HANDSHAKE);

  len = zt_msg_data_len(conn->msgbuf);

  rawptr = zt_msg_data_ptr(conn->msgbuf);
  rawptr[len++] = MSG_END; /* end of data */

  if ((conn->state == CLIENT_TRANSFER) && config.config_length_obfuscation) {
    size_t padding;

    taglen = vcry_get_aead_tag_len();

    padding = (len - 1) & (config.padding_factor - 1);
    zt_memset(rawptr + len, 0x00, padding); // FIX: possible side-channel?
    len += padding;
  }

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

  if (zt_client_tcp_send(conn, rawptr, tosend) != 0) {
    PRINTERROR("failed to send %zu bytes to peer_id=%s (%s)", tosend,
               config.peer_id, strerror(errno));
    return ERR_TCP_SEND;
  }

  zt_msg_set_len(conn->msgbuf, 0);

  return ERR_SUCCESS;
}

/**
 * @param[in] conn The client connection context.
 * @param[in] expect The expected message type.
 * @return An `error_t` status code.
 *
 * Receive a message from the peer and store it in `conn->msgbuf`.
 *
 * The type of the message (resulting `conn->msgbuf->type`) must match
 * @p expect.
 *
 * The amount of payload data to be read is indicated by a fixed-size header
 * prefix. If a failure occurs before all of this payload data is received
 * (either because of a timeout or other error), the function returns an error
 * code and sets the message length to 0.
 *
 * Encrypted payload data is decrypted in-place in `conn->msgbuf->data[]`.
 */
static error_t client_recv(zt_client_connection_t *conn, zt_msg_type_t expect) {
  error_t ret = ERR_SUCCESS;
  ssize_t nread;
  size_t datalen, taglen;
  uint8_t *rawptr, *dataptr;
  bool is_encrypted;

  ASSERT(conn);
  ASSERT(conn->state > CLIENT_CONN_INIT && conn->state <= CLIENT_DONE);
  ASSERT(conn->msgbuf);

  rawptr = zt_msg_raw_ptr(conn->msgbuf);
  dataptr = zt_msg_data_ptr(conn->msgbuf);

  /** Read the message header */
  nread = zt_client_tcp_recv(conn, rawptr, ZT_MSG_HEADER_SIZE, NULL);
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

  if (!msg_type_isvalid(zt_msg_type(conn->msgbuf) ||
                        (expect != zt_msg_type(conn->msgbuf)))) {
    PRINTERROR("invalid message type %u (expected %u)",
               zt_msg_type(conn->msgbuf), expect);
    ret = ERR_INVALID_DATUM;
    goto out;
  }

  is_encrypted = (zt_msg_type(conn->msgbuf) != MSG_HANDSHAKE);

  taglen = is_encrypted ? vcry_get_aead_tag_len() : 0;
  datalen = zt_msg_data_len(conn->msgbuf) + taglen;

  /** Read message payload */
  nread = zt_client_tcp_recv(conn, dataptr, datalen, NULL);
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

  /* Decrypt the payload if required */
  if (is_encrypted) {
    if ((ret = vcry_aead_decrypt(dataptr, datalen, rawptr, ZT_MSG_HEADER_SIZE,
                                 dataptr, &nread)) != ERR_SUCCESS) {
      PRINTERROR("decryption failed");
      goto out;
    }
  }

out:
  if (unlikely(ret))
    zt_msg_set_len(conn->msgbuf, 0);
  else
    zt_msg_set_len(conn->msgbuf, nread);

  return ret;
}

error_t zt_client_do(zt_client_connection_t *conn, void *args ATTRIBUTE_UNUSED,
                     bool *done) {
  error_t ret = ERR_SUCCESS;
  struct passwd *master_pass;
  zt_fileinfo_t fileinfo;
  zt_fio_t *fileptr;

  if (!conn || !done)
    return ERR_NULL_PTR;

  /** Allocate memory for primary client message buffer */
  if (!(conn->msgbuf = zt_malloc(sizeof(zt_msg_t))))
    return ERR_MEM_FAIL;

  /**
   * Load the master password and setup the VCRY engine
   */

  if (!(master_pass = zt_auth_passwd_new(config.passwddb_file, config.auth_type,
                                         config.peer_id))) {
    zt_free(conn->msgbuf);
    conn->msgbuf = NULL;
    return ERR_INTERNAL;
  }

  vcry_set_role_initiator();

  if ((ret = vcry_set_authpass(master_pass->pw, master_pass->pwlen)) !=
      ERR_SUCCESS) {
    goto cleanup;
  }

  zt_auth_passwd_free(master_pass, NULL);

  vcry_set_cipher_from_name(config.cipher_alg);
  vcry_set_aead_from_name(config.aead_alg);
  vcry_set_hmac_from_name(config.hmac_alg);
  vcry_set_ecdh_from_name(config.ecdh_alg);
  vcry_set_kem_from_name(config.kem_alg);
  vcry_set_kdf_from_name(config.kdf_alg);

  if ((ret = vcry_get_last_err()) != ERR_SUCCESS)
    goto cleanup;

  for (;;) {
    switch (conn->state) {
    case CLIENT_CONN_INIT: {
      struct zt_addrinfo *ai_list = NULL;

      if ((ret = zt_client_resolve_host_timeout(
               conn, &ai_list,
               (conn->resolve_timeout > 0) ? conn->resolve_timeout
                                           : ZT_CLIENT_TIMEOUT_RESOLVE)) !=
          ERR_SUCCESS) {
        goto cleanup;
      }

      if ((ret = zt_client_tcp_conn0(conn, ai_list)) != ERR_SUCCESS)
        goto cleanup;

      if ((ret = zt_client_tcp_conn1(conn)) != ERR_SUCCESS)
        goto cleanup;

      CLIENTSTATE_CHANGE(conn->state, CLIENT_AUTH_PING);
      break;
    }

    case CLIENT_AUTH_PING: {
      uint8_t *sndbuf;
      size_t sndbuf_len;

      if ((ret = vcry_handshake_initiate(&sndbuf, &sndbuf_len)) != ERR_SUCCESS)
        goto cleanup;

      /** Check if the connect() was successful and we have a writable socket
       */
      if (!zt_tcp_io_waitfor_write(conn->sockfd, conn->connect_timeout)) {
        zt_free(sndbuf);
        ret = ERR_TCP_CONNECT;
        goto cleanup;
      }

      zt_memcpy(zt_msg_data_ptr(conn->msgbuf), config.authid_mine.bytes,
                AUTHID_LEN_BYTES);

      zt_memcpy(zt_msg_data_ptr(conn->msgbuf) + AUTHID_LEN_BYTES, sndbuf,
                sndbuf_len);

      zt_free(sndbuf);

      zt_msg_set_len(conn->msgbuf, sndbuf_len + AUTHID_LEN_BYTES);
      zt_msg_set_type(conn->msgbuf, MSG_HANDSHAKE);

      if ((ret = client_send(conn)) != ERR_SUCCESS)
        goto cleanup;

      CLIENTSTATE_CHANGE(conn->state, CLIENT_AUTH_PONG);
      break;
    }

    case CLIENT_AUTH_PONG: {
      uint8_t *rcvbuf, *sndbuf;
      size_t rcvlen, sndlen;

      if ((ret = client_recv(conn, MSG_HANDSHAKE)) != ERR_SUCCESS)
        goto cleanup;

      rcvlen = zt_msg_get_len(conn->msgbuf);
      rcvbuf = zt_msg_data_ptr(conn->msgbuf);

      if (rcvlen < AUTHID_LEN_BYTES + VCRY_VERIFY_MSG_LEN) {
        return ERR_INVALID_DATUM;
        goto cleanup;
      }

      /* copy peer authid */
      zt_memcpy(&config.authid_peer, rcvbuf, AUTHID_LEN_BYTES);

      rcvbuf += AUTHID_LEN_BYTES;
      rcvlen -= AUTHID_LEN_BYTES;

      /* process handshake response */
      if ((ret = vcry_handshake_complete(
               rcvbuf, rcvlen - VCRY_VERIFY_MSG_LEN)) != ERR_SUCCESS) {
        goto cleanup;
      }

      if ((ret = vcry_derive_session_key()) != ERR_SUCCESS)
        goto cleanup;

      /* create our verify-initiation message */
      if ((ret = vcry_initiator_verify_initiate(
               &sndbuf, &sndlen, config.authid_mine.bytes,
               config.authid_peer.bytes)) != ERR_SUCCESS) {
        goto cleanup;
      }

      zt_msg_make(conn->msgbuf, MSG_HANDSHAKE, sndbuf, sndlen);

      zt_free(sndbuf);

      /* process the responder's verify-initiation message and complete
       * the verification on our end */
      if ((ret = vcry_initiator_verify_complete(
               rcvbuf + (ptrdiff_t)(rcvlen - VCRY_VERIFY_MSG_LEN),
               config.authid_mine.bytes, config.authid_peer.bytes)) !=
          ERR_SUCCESS) {
        goto cleanup;
      }

      /* send our verify-initiation message to the peer */
      if ((ret = client_send(conn)) != ERR_SUCCESS)
        goto cleanup;

      CLIENTSTATE_CHANGE(conn->state, CLIENT_TRANSFER);
      break;
    }

    case CLIENT_OFFER: {
      /**
       * Open the and lock the file here, so that its size remains fixed until
       * the entire file is sent
       */
      if ((ret = zt_fio_open(&fileptr, config.filename, FIO_RDONLY)) !=
          ERR_SUCCESS) {
        goto cleanup;
      }

      if ((ret = zt_fio_fileinfo(fileptr, &fileinfo)) != ERR_SUCCESS) {
        zt_fio_close(fileptr);
        goto cleanup;
      }

      fileinfo.size = hton64(fileinfo.size);
      fileinfo.reserved = hton32(fileinfo.reserved);
      zt_msg_make(conn->msgbuf, MSG_METADATA, (void *)&fileinfo,
                  sizeof(zt_fileinfo_t));
      memzero(&fileinfo, sizeof(zt_fileinfo_t));

      if ((ret = client_send(conn)) != ERR_SUCCESS) {
        zt_fio_close(fileptr);
        goto cleanup;
      }

      CLIENTSTATE_CHANGE(conn->state, CLIENT_TRANSFER);
      break;
    }

    case CLIENT_TRANSFER: {
      size_t nread;
      error_t rv;

      zt_msg_set_type(conn->msgbuf, MSG_DATA);
      for (;;) {
        rv = zt_fio_read(&fileptr, zt_msg_data_ptr(conn->msgbuf),
                         ZT_MAX_TRANSFER_SIZE, &nread);
        if (rv != ERR_SUCCESS)
          break;

        zt_msg_set_len(conn->msgbuf, nread);

        if ((ret = client_send(conn)) != ERR_SUCCESS) {
          zt_fio_close(&fileptr);
          goto cleanup;
        }
      }

      zt_fio_close(&fileptr);

      if (rv != ERR_EOF) {
        ret = rv;
        goto cleanup;
      }

      CLIENTSTATE_CHANGE(conn->state, CLIENT_DONE);
      break;
    }

    case CLIENT_DONE: {
      zt_msg_make(conn->msgbuf, MSG_DONE, PTR8("BYE"), 4);

      if ((ret = client_send(conn)) != ERR_SUCCESS)
        goto cleanup;

      CLIENTSTATE_CHANGE(conn->state, CLIENT_NONE);
      *done = true;
      goto cleanup;
    }

    default: {
      PRINTERROR("bad value for client state");
      ret = ERR_INVALID;
      goto cleanup;
    }
    }
  }

cleanup:
  shutdown(conn, SHUT_RDWR);
  close(conn->sockfd);
  conn->sockfd = -1;

  zt_addrinfo_free(conn->ai_estab);
  conn->ai_estab = NULL;

  vcry_module_release();

  zt_free(conn->msgbuf);
  conn->msgbuf = NULL;

  return ret;
}
