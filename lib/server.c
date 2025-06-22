
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
    [SERVER_AUTH_WAIT] = "SERVER_AUTH_WAIT",
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

static error_t server_read(zt_server_connection_t *conn, const uint8_t *aad, size_t aad_len) {

}

