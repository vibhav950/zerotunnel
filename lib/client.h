#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "conn_defs.h"

#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef enum {
  ZT_CLIENTSTATE_CONN_INIT,
  ZT_CLIENTSTATE_AUTH_INIT,
  ZT_CLIENTSTATE_CONN_DONE,
  ZT_CLIENTSTATE_PEERAUTH_WAIT,
  ZT_CLIENTSTATE_TRANSFER,
  ZT_CLIENTSTATE_DONE
} ZT_CLIENTSTATE;

typedef struct {
  ZT_CLIENTSTATE
    state;
  struct zt_addrinfo
    *ai_estab;
  struct sockaddr_in
    *addr_ipv4;
#ifdef USE_IPV6
  struct sockaddr_in6
    *addr_ipv6;
#endif
#if 1 // USE_SIGACT_TIMEOUT
  zt_timeval_t
    created_at;
#endif
  char
    *hostname;
  int
    sockfd,
    sock_flags,
    serv_port;
  // TODO make sure uninitialized values are set to -1
  int
    resolve_timeout,
    connect_timeout,
    send_timeout,
    recv_timeout;
  int
    tcp_fastopen : 1;
  // TODO move the config flags to a separate struct and only keep
  // status flags here (e.g. `ipv6_enabled : 1` indicating ipv6 enabled)
  bool
    config_ipv6 : 1, /* enable IPv6 addressing */
    config_port : 1, /* use explicit port */
    config_tcp_nodelay : 1, /* enable TCP_NODELAY */
    config_tcp_fastopen : 1, /* enable TCP_FASTOPEN */
    config_live_read : 1; /* live read enabled */
} cconnctx;

int zt_client_do(cconnctx *ctx, void *args, bool *done);

error_t zt_client_resolve_host_timeout(cconnctx *ctx, struct zt_addrinfo **ai_head, zt_timeout_t timeout_sec);

void zt_addrinfo_free(struct zt_addrinfo *ai);

void zt_addrinfo_set_port(struct zt_addrinfo *ai, int port);

error_t zt_client_tcp_conn0(cconnctx *ctx, struct zt_addrinfo *ai_list);

#endif /* __CLIENT_H__ */