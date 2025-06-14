#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "conn_defs.h"

#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef enum {
  CLIENT_NONE = 0,
  CLIENT_CONN_INIT,
  CLIENT_AUTH_PING,
  CLIENT_AUTH_PONG,
  CLIENT_OFFER,
  CLIENT_TRANSFER,
  CLIENT_DONE
} ZT_CLIENT_STATE;

typedef struct {
  ZT_CLIENT_STATE
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
  zt_msg_t
    *msgbuf;
  char
    *hostname;
  int
    sockfd,
    sock_flags,
    serv_port;
  int
    resolve_timeout,
    connect_timeout,
    send_timeout,
    recv_timeout;
  bool
    fl_tcp_fastopen   : 1,  /* is TCP fastopen enabled */
    fl_ipv6           : 1,  /* use IPv6 addressing */
    fl_explicit_port  : 1,  /* use explicit port */
    fl_tcp_nodelay    : 1,  /* is TCP_NODELAY enabled */
    fl_live_read      : 1;  /* is live read enabled */
} zt_client_connection_t;

error_t zt_client_resolve_host_timeout(zt_client_connection_t *conn,
                                       struct zt_addrinfo **ai_list,
                                       timediff_t timeout_sec);

error_t zt_client_tcp_conn0(zt_client_connection_t *conn,
                            struct zt_addrinfo *ai_list);

error_t zt_client_tcp_conn1(zt_client_connection_t *conn);

error_t client_send(zt_client_connection_t *conn, const uint8_t *aad,
                    size_t aad_len);

error_t client_recv(zt_client_connection_t *conn, zt_msg_type_t type,
                    const uint8_t *aad, size_t aad_len);

error_t zt_client_do(zt_client_connection_t *conn, void *args, bool *done);

#endif /* __CLIENT_H__ */
