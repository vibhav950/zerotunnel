#include "client.h"
#include "auth.h"
#include "common/defines.h"
#include "vcry.h"
#include "ztlib.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#define CLIENTSTATE_CHANGE(cur, next) (void)(cur = next)

static const char clientstate_names[][20] = {
    [CLIENT_NONE] = "CLIENT_NONE",
    [CLIENT_CONN_INIT] = "CLIENT_CONN_INIT",
    [CLIENT_AUTH_PING] = "CLIENT_AUTH_PING",
    [CLIENT_AUTH_PONG] = "CLIENT_AUTH_PONG",
    [CLIENT_TRANSFER] = "CLIENT_TRANSFER",
    [CLIENT_DONE] = "CLIENT_DONE"
};

static sigjmp_buf jmpenv;
static atomic_bool jmpenv_lock;

ATTRIBUTE_NORETURN static void alrm_handler(int sig ATTRIBUTE_UNUSED) {
  siglongjmp(jmpenv, 1);
}

static inline const char *get_clientstate_name(ZT_CLIENT_STATE state) {
  ASSERT(state >= CLIENT_NONE && state <= CLIENT_DONE);
  return clientstate_names[state];
}

static inline bool msg_type_isvalid(ZT_MSG_TYPE type) {
  return type >= MSG_HANDSHAKE && type <= MSG_DONE;
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
    PRINTERROR("getaddrinfo failed for %s: %s", conn->hostname,
               gai_strerror(status));
    if (status == EAI_SYSTEM) {
      PRINTERROR("getaddrinfo failed for %s (%s)", conn->hostname,
                 strerror(errno));
    }
    return ERR_INTERNAL;
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

  /* If there was an error, free the my_addrinfo list */
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

    if ((sockfd = socket(ai_cur->ai_family, SOCK_STREAM, IPPROTO_TCP))) {
      PRINTERROR("socket failed (%s)", strerror(errno));
      continue;
    }

    /** Try to enable TCP_NODELAY */
#ifdef TCP_NODELAY
    on = 1;
    if (conn->fl_tcp_nodelay) {
      if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("setsockopt failed to set TCP_NODELAY (%s)",
                   strerror(errno));
        conn->fl_tcp_nodelay = false;
      }
    }
#endif

    /** Try to enable TCP_FASTOPEN */
#ifdef TCP_FASTOPEN_CONNECT /* Linux >= 4.11 */
    if (conn->fl_tcp_fastopen) {
      on = 1;
      if (setsockopt(conn->sockfd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                     (void *)&on, sizeof(on)) == -1) {
        PRINTERROR("setsockopt failed to set TCP_FASTOPEN_CONNECT (%s)",
                   strerror(errno));
        conn->fl_tcp_fastopen = false;
      }
    }
#endif

    /** We must have TCP keepalive enabled for live reads */
    if (conn->fl_live_read) {
      int fail = 0;

      on = 1;
      if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("setsockopt failed to set SO_KEEPALIVE (%s)",
                   strerror(errno));
        fail = 1;
      }

      if (getsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("getsockopt failed to get SO_KEEPALIVE (%s)",
                   strerror(errno));
        fail = 1;
      }

      if (fail || !on) {
        PRINTERROR("could not prepare socket for live read");
        close(sockfd);
        continue;
      }
    }

    /** Try to enable send */
    if (conn->send_timeout > 0) {
      struct timeval tval = {.tv_sec = conn->send_timeout / 1000,
                             .tv_usec = (conn->send_timeout % 1000) * 1000};
      if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tval,
                     sizeof(tval)) == -1) {
        PRINTERROR("setsockopt failed to set SO_SNDTIMEO (%s)",
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
        PRINTERROR("setsockopt failed to set SO_RCVTIMEO (%s)",
                   strerror(errno));
        close(sockfd);
        continue;
      }
    }

    /* If nothing failed we have found a valid candidate */
    ai_estab = zt_malloc(sizeof(struct zt_addrinfo));
    if (ai_estab) {
      zt_memcpy(ai_estab, ai_cur, sizeof(struct zt_addrinfo));
      ai_estab->ai_next = NULL;
      conn->sockfd = sockfd;
      conn->ai_estab = ai_estab;
      break;
    } else {
      ret = ERR_MEM_FAIL;
      goto exit;
    }
  }

  if (!ai_estab)
    ret = ERR_NORESOLVE;

exit:
  if (ret) {
    conn->sockfd = -1;
    close(sockfd);
  }
  freeaddrinfo(ai_list);
  return ret;
}

static inline error_t zt_client_tcp_conn1(zt_client_connection_t *conn) {
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
  conn->sock_flags = flags = fnctl(sockfd, F_GETFL, 0);
  fnctl(sockfd, F_SETFL, flags | O_NONBLOCK);

  ai_estab = conn->ai_estab;
  rv = connect(conn->sockfd, ai_estab->ai_addr, ai_estab->ai_addrlen);
  if (rv == -1 && errno != EAGAIN && errno != EINPROGRESS) {
    PRINTERROR("connect failed (%s)", strerror(errno));
    close(conn->sockfd);
    return ERR_TCP_CONNECT;
  }
  /**
   * We are done for now, but it is important to verify the connection
   * before performing a read/write and restore the file status flags then
   */
  return ERR_SUCCESS;
}

/**
 * @param[in] conn The client connection context.
 * @param[in] aad The additional authenticated data.
 * @param[in] aad_len The length of the additional authenticated data.
 * @return An `error_t` status code.
 *
 * Send data present in `conn->msgbuf->data` to the peer. This function will
 * encrypt the payload before sending it if the client is in the
 * `CLIENT_TRANSFER` state whereas handshake messages are sent as-is.
 *
 * If a failure occurs before all of the `conn->msgbuf->len` bytes of date are
 * sent (either because of a timeout or other error), the function returns an
 * `ERR_TCP_SEND`.
 *
 * The @p aad and @p aad_len arguments are ignored if the client state is not
 * `CLIENT_TRANSFER`.
 */
static error_t client_send(zt_client_connection_t *conn, const uint8_t *aad,
                           size_t aad_len) {
  error_t ret;
  ssize_t tosend, nbytes;
  uint8_t *databuf;

  ASSERT(conn);
  ASSERT(conn->state > CLIENT_CONN_INIT && conn->state < CLIENT_DONE);
  ASSERT(conn->msgbuf);
  ASSERT(conn->msgbuf->len <= ZT_MAX_TRANSFER_SIZE);
  ASSERT(!aad_len || aad); /* can't have `aad == NULL` when `aad_len > 0` */

  databuf = zt_msg_data_ptr(conn->msgbuf);
  nbytes = (ssize_t)zt_msg_data_len(conn->msgbuf);

  if (conn->state == CLIENT_TRANSFER) {
    tosend = ZT_MAX_TRANSFER_SIZE;
    if ((ret = vcry_aead_encrypt(databuf, nbytes, aad, aad_len, databuf,
                                 &tosend)) != ERR_SUCCESS) {
      PRINTERROR("failed to encrypt %zu bytes of payload", nbytes,
                 config.peer_id);
      return ret;
    }
    tosend = tosend /*msgbuf.data*/ + sizeof(uint32_t) /*msgbuf.type*/;
  } else {
    tosend = nbytes + sizeof(uint32_t);
  }
  zt_msg_set_len(conn->msgbuf, 0);

  if (zt_client_tcp_send(conn, zt_msg_raw_ptr(conn->msgbuf), tosend) != 0) {
    PRINTERROR("failed to send %zu bytes to peer_id=%s (%s)", tosend,
               config.peer_id, strerror(errno));
    return ERR_TCP_SEND;
  }

  return ERR_SUCCESS;
}

/**
 * @param[in] conn The client connection context.
 * @param[in] expect The expected message type.
 * @param[in] aad The additional authenticated data.
 * @param[in] aad_len The length of the additional authenticated data.
 * @return An `error_t` status code.
 *
 * Read @p expect bytes from the peer into `conn->msgbuf->data` and set
 * `conn->msgbuf->len` to the length of the received `conn->msgbuf->data`.
 *
 * If @p expect is -1, the function will read as much data as possible from the
 * underlying socket.
 *
 * The message type is extracted from the first 4 bytes of the message and
 * stored in the `conn->msgbuf->type`.
 *
 * If the client is in the `CLIENT_TRANSFER` state, the data is decrypted before
 * being returned to the caller. Handshake messages are returned as-is.
 *
 * If the client state is not `CLIENT_TRANSFER`, the @p aad and @p aad_len
 * arguments are ignored.
 */
static error_t client_recv(zt_client_connection_t *conn, ZT_MSG_TYPE expect,
                           const uint8_t *aad, size_t aad_len) {
  error_t ret;
  ssize_t nread, outlen;
  size_t max_recv;
  uint8_t *buf;

  ASSERT(conn);
  ASSERT(conn->state > CLIENT_CONN_INIT && conn->state < CLIENT_DONE);
  ASSERT(conn->msgbuf);

  max_recv = ZT_MAX_TRANSFER_SIZE + 64;
  buf = zt_msg_raw_ptr(conn->msgbuf);
  if ((nread = zt_client_tcp_recv(conn, buf, max_recv, NULL)) < 0) {
    PRINTERROR("failed to read data from peer_id=%s (%s)", config.peer_id,
               strerror(errno));
    return ERR_TCP_RECV;
  }

  if (nread < sizeof(uint32_t) ||
      !msg_type_isvalid(zt_msg_get_type(conn->msgbuf))) {
    PRINTERROR("invalid message type prefix", nread, config.peer_id);
    return ERR_INVALID_DATUM;
  }

  if (expect != zt_msg_get_type(conn->msgbuf)) {
    PRINTERROR("unexpected message type %u (expected %u)", nread,
               config.peer_id, zt_msg_get_type(conn->msgbuf), expect);
    return ERR_INVALID_DATUM;
  }

  nread -= sizeof(uint32_t); /* without the message type */

  buf = zt_msg_data_ptr(conn->msgbuf);
  if (conn->state == CLIENT_TRANSFER) {
    if ((ret = vcry_aead_decrypt(buf, nread, aad, aad_len, buf, &outlen)) !=
        ERR_SUCCESS) {
      PRINTERROR("failed to decrypt %zu bytes of payload", nread,
                 config.peer_id);
      return ret;
    }
    nread = outlen;
  }

  zt_msg_set_len(conn->msgbuf, nread);

  return ERR_SUCCESS;
}

error_t zt_client_do(zt_client_connection_t *conn, void *args, bool *done) {
  error_t ret;

  if (unlikely(!conn || !done))
    return ERR_NULL_PTR;

  switch (conn->state) {
  case CLIENT_CONN_INIT: {
    struct zt_addrinfo *ai_list = NULL;

    if ((ret = zt_client_resolve_host_timeout(
             conn, &ai_list,
             (conn->resolve_timeout > 0) ? conn->resolve_timeout
                                         : ZT_CLIENT_TIMEOUT_RESOLVE)) !=
        ERR_SUCCESS) {
      return ret;
    }

    if ((ret = zt_client_tcp_conn0(conn, ai_list)) != ERR_SUCCESS)
      return ret;

    if ((ret = zt_client_tcp_conn1(conn)) != ERR_SUCCESS)
      return ret;

    /** Allocate client message buffer */
    if (!(conn->msgbuf = zt_malloc(sizeof(zt_msg_t))))
      return ERR_MEM_FAIL;

    CLIENTSTATE_CHANGE(conn->state, CLIENT_AUTH_PING);
    return ERR_SUCCESS;
  }

  case CLIENT_AUTH_PING: {
    struct passwd *master_pass;
    uint8_t *sndbuf;
    size_t sndbuf_len;

    if (!(master_pass = zt_auth_passwd_new(config.passwddb_file,
                                           config.auth_type, config.peer_id))) {
      return ERR_INTERNAL;
    }

    vcry_set_role_initiator();

    if ((ret = vcry_set_authpass(master_pass->pw, master_pass->pwlen)) !=
        ERR_SUCCESS) {
      return ret;
    }

    zt_auth_passwd_free(master_pass, NULL);

    vcry_set_cipher_from_name(config.cipher_alg);
    vcry_set_aead_from_name(config.aead_alg);
    vcry_set_hmac_from_name(config.hmac_alg);
    vcry_set_ecdh_from_name(config.ecdh_alg);
    vcry_set_kem_from_name(config.kem_alg);
    vcry_set_kdf_from_name(config.kdf_alg);

    if ((ret = vcry_get_last_err()) != ERR_SUCCESS)
      return ret;

    if ((ret = vcry_handshake_initiate(&sndbuf, &sndbuf_len)) != ERR_SUCCESS)
      return ret;

    /** Check if the connect() was successful and we have a writable socket */
    if (!zt_tcp_io_waitfor_write(conn->sockfd, conn->connect_timeout))
      return ERR_TCP_CONNECT;

    zt_memcpy(zt_msg_data_ptr(conn->msgbuf), config.authid_mine.bytes,
              AUTHID_LEN_BYTES);

    zt_memcpy(zt_msg_data_ptr(conn->msgbuf) + AUTHID_LEN_BYTES, sndbuf,
              sndbuf_len);

    zt_msg_set_len(conn->msgbuf, sndbuf_len + AUTHID_LEN_BYTES);
    zt_msg_set_type(conn->msgbuf, MSG_HANDSHAKE);

    if ((ret = client_send(conn, NULL, 0)) != ERR_SUCCESS)
      return ret;

    CLIENTSTATE_CHANGE(conn->state, CLIENT_AUTH_PONG);
    return ERR_SUCCESS;
  }

  case CLIENT_AUTH_PONG: {
    uint8_t *rcvbuf, *sndbuf;
    size_t rcvlen, sndlen;

    /* read [AUTHID_LEN_BYTES]][...][VCRY_VERIFY_MSG_LEN] */
    if ((ret = client_recv(conn, MSG_HANDSHAKE, NULL, 0)) != ERR_SUCCESS)
      return ret;

    rcvlen = zt_msg_get_len(conn->msgbuf);
    rcvbuf = zt_msg_data_ptr(conn->msgbuf);

    if (rcvlen < AUTHID_LEN_BYTES + VCRY_VERIFY_MSG_LEN)
      return ERR_INVALID_DATUM;

    /* extract [AUTHID_LEN_BYTES] */
    zt_memcpy(&config.authid_peer, rcvbuf, AUTHID_LEN_BYTES);

    rcvbuf += AUTHID_LEN_BYTES;
    rcvlen -= AUTHID_LEN_BYTES;

    if ((ret = vcry_handshake_complete(rcvbuf, rcvlen - VCRY_VERIFY_MSG_LEN)) !=
        ERR_SUCCESS) {
      return ret;
    }

    if ((ret = vcry_derive_session_key()) != ERR_SUCCESS)
      return ret;

    if ((ret = vcry_initiator_verify_initiate(
             &sndbuf, &sndlen, config.authid_mine.bytes,
             config.authid_peer.bytes)) != ERR_SUCCESS) {
      return ret;
    }

    zt_memcpy(zt_msg_data_ptr(conn->msgbuf), sndbuf, sndlen);
    zt_msg_set_len(conn->msgbuf, sndlen);
    zt_msg_set_type(conn->msgbuf, MSG_HANDSHAKE);

    /* extract [VCRY_VERIFY_MSG_LEN] */
    if ((ret = vcry_initiator_verify_complete(
             rcvbuf + (ptrdiff_t)(rcvlen - VCRY_VERIFY_MSG_LEN),
             config.authid_mine.bytes, config.authid_peer.bytes)) !=
        ERR_SUCCESS) {
      return ret;
    }

    if ((ret = client_send(conn, NULL, 0)) != ERR_SUCCESS)
      return ret;

    CLIENTSTATE_CHANGE(conn->state, CLIENT_TRANSFER);
    return ERR_SUCCESS;
  }

  case CLIENT_TRANSFER: {
  }

  default:
    return ERR_INVALID;
  }
}
