#include "client.h"
#include "common/zerotunnel.h"

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
    "ZT_CLIENTSTATE_CONN_INIT", "ZT_CLIENTSTATE_AUTH_INIT",
    "ZT_CLIENTSTATE_CONN_DONE", "ZT_CLIENTSTATE_PEERAUTH_WAIT",
    "ZT_CLIENTSTATE_TRANSFER",  "ZT_CLIENTSTATE_DONE"};

static sigjmp_buf jmpenv;
static atomic_bool jmpenv_lock;

ATTRIBUTE_NORETURN static void alrm_handler(int sig ATTRIBUTE_UNUSED) {
  siglongjmp(jmpenv, 1);
}

error_t zt_client_resolve_host_timeout(cconnctx *ctx,
                                       struct zt_addrinfo **ai_list,
                                       timediff_t timeout_msec) {
  error_t ret = ERR_SUCCESS;
  struct zt_addrinfo *ai_head = NULL, *ai_cur;
  struct addrinfo hints, *res = NULL, *p;
  size_t saddr_len;
  int status;
  bool use_ipv6;
  char ipstr[INET6_ADDRSTRLEN];

#if 1 // USE_SIGACT_TIMEOUT
  struct sigaction sigact, sigact_old;
  volatile bool have_old_sigact = false;
  volatile long timeout;
  volatile unsigned int prev_alarm = 0;
#endif

  assert(ctx);
  assert(ctx->state == ZT_CLIENTSTATE_CONN_INIT);
  assert(timeout_msec > 0);

  if (!ctx->hostname) {
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

  /* Check if the system has IPv6 enabled */
  use_ipv6 = false;
#ifdef USE_IPV6
  if (ctx->config_ipv6) {
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s != -1) {
      use_ipv6 = true;
      close(s);
    }
  }
#endif

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = use_ipv6 ? AF_UNSPEC : AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  // TODO we need some kind of logic here for when hostnames need resolving
  hints.ai_flags = NI_NUMERICHOST | NI_NUMERICSERV;

  for (int ntries = 0; ntries < CLIENT_RESOLVE_RETRIES; ntries++) {
    status = getaddrinfo(ctx->hostname, NULL, &hints, &res);

    if (status == 0 || status != EAI_AGAIN)
      break;

    if (ntries < CLIENT_RESOLVE_RETRIES - 1)
      sleep(1);
  }

  if (status) {
    PRINTERROR("getaddrinfo(3) failed for %s: %s\n", ctx->hostname,
               gai_strerror(status));
    if (status == EAI_SYSTEM) {
      PRINTERROR("getaddrinfo(3) failed for %s (%s)\n", ctx->hostname,
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
    else if (use_ipv6 && (p->ai_family == AF_INET6)) {
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
    ai_cur = malloc(sizeof(struct zt_addrinfo) + cname_len + saddr_len);
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
    memcpy(ai_cur->ai_addr, p->ai_addr, saddr_len);

    if (cname_len) {
      ai_cur->ai_canonname = (void *)((char *)ai_cur->ai_addr + saddr_len);
      memcpy(ai_cur->ai_canonname, p->ai_canonname, cname_len);
    }

    if (!ai_head)
      ai_head = ai_cur;

    PRINTDEBUG("Resolved %s to %s\n", ctx->hostname,
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
        zt_timediff_msec(zt_time_now(), ctx->created_at) / 1000;

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

error_t zt_client_tcp_conn0(cconnctx *ctx, struct zt_addrinfo *ai_list) {
  error_t ret = ERR_SUCCESS;
  struct zt_addrinfo *ai_cur, *ai_estab;
  int sockfd, on;

  assert(ctx);
  assert(ctx->state == ZT_CLIENTSTATE_CONN_INIT);
  assert(ai_list);

  for (ai_cur = ai_list; ai_cur; ai_cur = ai_cur->ai_next) {
    int fail = 0;

    if ((sockfd = socket(ai_cur->ai_family, SOCK_STREAM, IPPROTO_TCP))) {
      PRINTERROR("socket(2) failed (%s)\n", strerror(errno));
      continue;
    }

#ifdef TCP_NODELAY
    on = 1;
    if (ctx->config_tcp_nodelay) {
      if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("setsockopt(2) failed to set TCP_NODELAY (%s)\n",
                   strerror(errno));
      }
    }
#endif

#ifdef TCP_FASTOPEN_CONNECT /* Linux >= 4.11 */
    if (ctx->config_tcp_fastopen) {
      on = 1;
      if (setsockopt(ctx->sockfd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                     (void *)&on, sizeof(on)) == -1) {
        PRINTERROR("setsockopt(2) failed to set TCP_FASTOPEN_CONNECT (%s)\n",
                   strerror(errno));
      }
    }
#endif

    /** We must have TCP keepalive enabled for live reads */
    if (ctx->config_live_read) {
      int lrfail = 0;

      on = 1;
      if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("setsockopt(2) failed to set SO_KEEPALIVE (%s)\n",
                   strerror(errno));
        lrfail = 1;
      }

      if (getsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
                     sizeof(on)) == -1) {
        PRINTERROR("getsockopt(2) failed to get SO_KEEPALIVE (%s)\n",
                   strerror(errno));
        lrfail = 1;
      }

      if (lrfail || !on) {
        PRINTERROR("Could not prepare socket for live read\n");
        close(sockfd);
        continue;
      }
    }

    if (ctx->send_timeout > 0) {
      struct timeval tval = {.tv_sec = ctx->send_timeout / 1000,
                             .tv_usec = (ctx->send_timeout % 1000) * 1000};
      if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tval,
                     sizeof(tval)) == -1) {
        PRINTERROR("setsockopt(2) failed to set SO_RCVTIMEO (%s)\n",
                   strerror(errno));
      }
    }

    if (ctx->recv_timeout > 0) {
      struct timeval tval = {.tv_sec = ctx->recv_timeout / 1000,
                             .tv_usec = (ctx->recv_timeout % 1000) * 1000};
      if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tval,
                     sizeof(tval)) == -1) {
        PRINTERROR("setsockopt(2) failed to set SO_SNDTIMEO (%s)\n",
                   strerror(errno));
      }
    }

    /* If nothing failed we have found a valid candidate */
    ctx->ai_estab = NULL;
    ai_estab = malloc(sizeof(struct zt_addrinfo));
    if (ai_estab) {
      memcpy(ai_estab, ai_cur, sizeof(struct zt_addrinfo));
      ai_estab->ai_next = NULL;
      ctx->sockfd = sockfd;
      ctx->ai_estab = ai_estab;
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
    ctx->sockfd = -1;
    close(sockfd);
  }
  freeaddrinfo(ai_list);
  return ret;
}

error_t client_tcp_conn1(cconnctx *ctx) {
  int rv, flags;
  int sockfd;
  struct zt_addrinfo *ai_estab;

  assert(ctx);
  assert(ctx->state == ZT_CLIENTSTATE_CONN_INIT);
  assert(ctx->ai_estab);
  assert(ctx->sockfd >= 0);

  /**
   * Make this connect non-blocking. We don't need a connection immediately
   * and instead of waiting can use the time for the handshake setup process
   */
  sockfd = ctx->sockfd;
  ctx->sock_flags = flags = fnctl(sockfd, F_GETFL, 0);
  fnctl(sockfd, F_SETFL, flags | O_NONBLOCK);

  ai_estab = ctx->ai_estab;
  rv = connect(ctx->sockfd, ai_estab->ai_addr, ai_estab->ai_addrlen);
  if (rv == -1 && errno != EAGAIN && errno != EINPROGRESS) {
    PRINTERROR("connect(2) failed (%s)\n", strerror(errno));
    close(ctx->sockfd);
    return ERR_CONNECT;
  }
  /**
   * We are done for now, but it is important to verify the connection
   * before performing a read/write and restore the file status flags then
   */
  return ERR_SUCCESS;
}

error_t client_tcp_verify(cconnctx *ctx, timediff_t timeout_msec) {
  error_t ret = ERR_SUCCESS;
  int flags, error;
  int sockfd;
  socklen_t len;
  fd_set rset, wset;
  struct timeval tval;

  assert(ctx);
  assert(ctx->state == ZT_CLIENTSTATE_AUTH_INIT);
  assert(ctx->sockfd >= 0);
  assert(timeout_msec >= 0);

  sockfd = ctx->sockfd;
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
    fnctl(sockfd, F_SETFL, ctx->sock_flags); /* Restore file status flags */
  return ret;
}

// TODO handle *done
// TODO handle error_t errors, this function will only return 0 or -1

// This is the client state machine; the idea is to call zt_client_do from the
// main routine with different arguments required for different states. This way
// we can have some nice async behaviour while building the connection
int zt_client_do(cconnctx *ctx, void *args, bool *done) {
  int rv;

  if (!ctx) {
    PRINTERROR("NULL client ctx\n");
    return ERR_NULL_PTR;
  }

  switch (ctx->state) {
  case ZT_CLIENTSTATE_CONN_INIT: {
    struct zt_addrinfo *ai_list = NULL;

    if ((rv = zt_client_resolve_host_timeout(
             ctx, &ai_list,
             (ctx->resolve_timeout > 0) ? ctx->resolve_timeout
                                        : ZT_CLIENT_TIMEOUT_RESOLVE)) != 0) {
      goto exit;
    }
    if ((rv = zt_client_tcp_conn0(ctx, ai_list)) != 0)
      goto exit;
    if ((rv = client_tcp_conn1(ctx)) != 0)
      goto exit;

    CLIENTSTATE_CHANGE(ctx->state, ZT_CLIENTSTATE_AUTH_INIT);
    goto exit;
  }

  case ZT_CLIENTSTATE_AUTH_INIT: {
    /**
     * We have arrived here with the required authentication parameters from
     * the user; so now would be the time to verify if connect() was
     * successful
     *
     * Note: A zero timeout is allowed in this case meaning that we will not
     * wait for the connection to be verified (expect a completed TCP
     * connection)
     */
    if ((rv = client_tcp_verify(ctx, (ctx->connect_timeout >= 0)
                                         ? ctx->connect_timeout
                                         : ZT_CLIENT_TIMEOUT_CONNECT)) != 0) {
      goto exit;
    }
  }
  }

exit:
  return rv;
}
