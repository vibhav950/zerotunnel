#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "auth.h"
#include "conn_defs.h"

typedef enum {
  CLIENT_NONE = 0,
  CLIENT_CONN_INIT,
  CLIENT_AUTH_INIT,
  CLIENT_AUTH_COMPLETE,
  CLIENT_OFFER,
  CLIENT_TRANSFER,
  CLIENT_DONE
} ZT_CLIENT_STATE;

// clang-format off
typedef struct _zt_client_connection_st {
  ZT_CLIENT_STATE
    state;
  struct zt_addrinfo
    *ai_estab;
#if 1 //def USE_SIGACT_TIMEOUT
  zt_timeval_t
    created_at;
#endif
  zt_msg_t
    *msgbuf;
  char
    *hostname,
    *explicit_port;
  struct authid
    authid_mine,   /* local AuthId */
    authid_peer;   /* peer's AuthId */
  passwd_id_t
    renegotiation_passwd;
  int
    sockfd,
    sock_flags,
    resolve_timeout,
    connect_timeout,
    send_timeout,
    recv_timeout;
  bool
    first_send,
    renegotiation;
  bool
    fl_tcp_fastopen   : 1,  /* is TCP fastopen enabled */
    fl_ipv6           : 1,  /* use IPv6 addressing */
    fl_explicit_port  : 1,  /* override default server port */
    fl_tcp_nodelay    : 1,  /* is TCP_NODELAY enabled */
    fl_live_read      : 1;  /* is live read enabled */
} zt_client_connection_t;
// clang-format on

err_t zt_client_run(zt_client_connection_t *conn, void *args, bool *done);

int zt_client_tcp_send(zt_client_connection_t *conn, const uint8_t *buf,
                       size_t nbytes);

ssize_t zt_client_tcp_recv(zt_client_connection_t *conn, uint8_t *buf,
                           size_t nbytes, bool *pending);

#endif /* __CLIENT_H__ */
