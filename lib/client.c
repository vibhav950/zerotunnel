#include "client.h"
#include "common/defines.h"

// #include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

// Temp defines for testing

// TODO
// add timeouts where required
// decide what functions must be static

#define CLIENTSTATE_CHANGE(cur, next) (void)(cur = next)

// TODO deal with this formatting
static const char clientstate_names[][20] = {
    "CLIENT_NONE",
    "CLIENT_CONN_INIT",
    "CLIENT_AUTH_INIT",
    "CLIENT_AUTH_WAIT",
    "CLIENT_CONN_DONE",
    "CLIENT_TRANSFER",
    "CLIENT_DONE"
};

static sigjmp_buf jmpenv;
static atomic_bool jmpenv_lock;

ATTRIBUTE_NORETURN static void alrm_handler(int sig ATTRIBUTE_UNUSED) {
  siglongjmp(jmpenv, 1);
}

error_t zt_client_resolve_host_timeout(zt_client_connection_t *conn,
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

  assert(conn);
  assert(conn->state == CLIENT_CONN_INIT);
  assert(timeout_msec > 0);

  if (!conn->hostname) {
    PRINTERROR("Empty hostname string\n");
    return ERR_NULL_PTR;
  }

#if 1 // USE_SIGACT_TIMEOUT
  if (atomic_flag_test_and_set(&jmpenv_lock))
    return ERR_ALREADY;

  if (sigsetjmp(jmpenv, 1)) {
    /** This is coming from a siglongjmp() after an alarm signal */
    PRINTERROR("Host resolution timed out\n");
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
     * This will cause a SIGALRM signal to be sent after `timeout_msec` in
     * seconds (rounded up) which will cause the system call to abort
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
  // TODO we need some kind of logic here for when hostnames need resolving
  hints.ai_flags = NI_NUMERICHOST | NI_NUMERICSERV;

  for (int ntries = 0; ntries < CLIENT_RESOLVE_RETRIES; ntries++) {
    status = getaddrinfo(conn->hostname, NULL, &hints, &res);

    if (status == 0 || status != EAI_AGAIN)
      break;

    if (ntries < CLIENT_RESOLVE_RETRIES - 1)
      sleep(1);
  }

  if (status) {
    PRINTERROR("getaddrinfo(3) failed for %s: %s\n", conn->hostname,
               gai_strerror(status));
    if (status == EAI_SYSTEM) {
      PRINTERROR("getaddrinfo(3) failed for %s (%s)\n", conn->hostname,
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

    PRINTDEBUG("Resolved %s to %s\n", conn->hostname,
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
      /** Set off the alarm; note that alarm(0) would switch it
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

error_t zt_client_tcp_conn0(zt_client_connection_t *conn, struct zt_addrinfo *ai_list) {
  error_t ret = ERR_SUCCESS;
  struct zt_addrinfo *ai_cur, *ai_estab = NULL;
  int sockfd, on;

  assert(conn);
  assert(conn->state == CLIENT_CONN_INIT);
  assert(ai_list);

  for (ai_cur = ai_list; ai_cur; ai_cur = ai_cur->ai_next) {
    int fail = 0;

    if ((sockfd = socket(ai_cur->ai_family, SOCK_STREAM, IPPROTO_TCP))) {
      PRINTERROR("socket(2) failed (%s)\n", strerror(errno));
      continue;
    }

    /** Try to enable TCP_NODELAY */
#ifdef TCP_NODELAY
    on = 1;
    if (conn->fl_tcp_nodelay) {
      if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("setsockopt(2) failed to set TCP_NODELAY (%s)\n",
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
        PRINTERROR("setsockopt(2) failed to set TCP_FASTOPEN_CONNECT (%s)\n",
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
        PRINTERROR("setsockopt(2) failed to set SO_KEEPALIVE (%s)\n",
                   strerror(errno));
        fail = 1;
      }

      if (getsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("getsockopt(2) failed to get SO_KEEPALIVE (%s)\n",
                   strerror(errno));
        fail = 1;
      }

      if (fail || !on) {
        PRINTERROR("Could not prepare socket for live read\n");
        close(sockfd);
        continue;
      }
    }

    /** Try to enable send  */
    if (conn->send_timeout > 0) {
      struct timeval tval = {.tv_sec = conn->send_timeout / 1000,
                             .tv_usec = (conn->send_timeout % 1000) * 1000};
      if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tval,
                     sizeof(tval)) == -1) {
        PRINTERROR("setsockopt(2) failed to set SO_SNDTIMEO (%s)\n",
                   strerror(errno));
        // close(sockfd);
        // continue;
      }
    }

    if (conn->recv_timeout > 0) {
      struct timeval tval = {.tv_sec = conn->recv_timeout / 1000,
                             .tv_usec = (conn->recv_timeout % 1000) * 1000};
      if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tval,
                     sizeof(tval)) == -1) {
        PRINTERROR("setsockopt(2) failed to set SO_RCVTIMEO (%s)\n",
                   strerror(errno));
        // close(sockfd);
        // continue;
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

error_t zt_client_tcp_conn1(zt_client_connection_t *conn) {
  int rv, flags;
  int sockfd;
  struct zt_addrinfo *ai_estab;

  assert(conn);
  assert(conn->state == CLIENT_CONN_INIT);
  assert(conn->ai_estab);
  assert(conn->sockfd >= 0);

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
    PRINTERROR("connect(2) failed (%s)\n", strerror(errno));
    close(conn->sockfd);
    return ERR_CONNECT;
  }
  /**
   * We are done for now, but it is important to verify the connection
   * before performing a read/write and restore the file status flags then
   */
  return ERR_SUCCESS;
}

error_t zt_client_tcp_verify(zt_client_connection_t *conn, timediff_t timeout_msec) {
  error_t ret = ERR_SUCCESS;
  int flags, error;
  int sockfd;
  socklen_t len;
  fd_set rset, wset;
  struct timeval tval;

  assert(conn);
  assert(conn->state == CLIENT_AUTH_INIT);
  assert(conn->sockfd >= 0);
  assert(timeout_msec >= 0);

  sockfd = conn->sockfd;
  FD_ZERO(&rset);
  FD_SET(sockfd, &rset);
  wset = rset;
  tval.tv_sec = timeout_msec / 1000;
  tval.tv_usec = (timeout_msec % 1000) * 1000;

  if (select(sockfd + 1, &rset, &wset, NULL,
             (timeout_msec > 0) ? &tval : NULL) == 0) {
    PRINTERROR("Connection timed out\n");
    close(sockfd);
    return ERR_TIMEOUT;
  }

  /** Verify that the socket is readable and writeable */
  if (FD_ISSET(sockfd, &rset) && FD_ISSET(sockfd, &wset)) {
    len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
      PRINTERROR("getsockopt(2) failed (%s)\n", strerror(errno));
      ret = ERR_CONNECT;
    }

    /** Check for pending socket error */
    if (error) {
      PRINTERROR("Connection failed (%s)\n", strerror(error));
      ret = ERR_CONNECT;
    }
  } else {
    /** Socket has not become readable/writeable yet, fail the connect */
    PRINTERROR("Connection failed\n");
    ret = ERR_CONNECT;
  }

  if (ret)
    close(sockfd);
  else
    fnctl(sockfd, F_SETFL, conn->sock_flags); /* Restore file status flags */
  return ret;
}

// TODO handle *done
// TODO handle error_t errors, this function will only return 0 or -1

// This is the client state machine; the idea is to call zt_client_do from the
// main routine with different arguments required for different states. This way
// we can have some nice async behaviour while building the connection
int zt_client_do(zt_client_connection_t *conn, void *args, bool *done) {
  int rv;

  if (!conn) {
    PRINTERROR("Client connection handle is NULL\n");
    return ERR_NULL_PTR;
  }

  switch (conn->state) {
  case CLIENT_CONN_INIT: {
    struct zt_addrinfo *ai_list = NULL;

    if ((rv = zt_client_resolve_host_timeout(
             conn, &ai_list,
             (conn->resolve_timeout > 0) ? conn->resolve_timeout
                                        : ZT_CLIENT_TIMEOUT_RESOLVE)) != 0) {
      goto exit;
    }
    if ((rv = zt_client_tcp_conn0(conn, ai_list)) != 0)
      goto exit;
    if ((rv = zt_client_tcp_conn1(conn)) != 0)
      goto exit;

    CLIENTSTATE_CHANGE(conn->state, CLIENT_AUTH_INIT);
    goto exit;
  }

  case CLIENT_AUTH_INIT: {
    /**
     * We have arrived here with the required authentication parameters from
     * the user; so now would be the time to verify if connect() was
     * successful
     *
     * Note: A zero timeout is allowed in this case meaning that we will not
     * wait for the connection to be verified (expect a completed TCP
     * connection)
     */
    if ((rv = zt_client_tcp_verify(conn, (conn->connect_timeout >= 0)
                                         ? conn->connect_timeout
                                         : ZT_CLIENT_TIMEOUT_CONNECT)) != 0) {
      goto exit;
    }


  }
  }

exit:
  return rv;
}
