#ifndef __SERVER_H__
#define __SERVER_H__

#include "conn_defs.h"

typedef enum {
  SERVER_NONE = 0,
  SERVER_CONN_INIT,
  SERVER_AUTH_WAIT,
  SERVER_COMMIT,
  SERVER_TRANSFER,
  SERVER_DONE
} ZT_SERVER_STATE;

// clang-format off
typedef struct _zt_server_connection_st {
  ZT_SERVER_STATE
    state;
  struct zt_addrinfo
    *ai_estab;        /* established address */
  char
    *hostname;        /* stated hostname string; if NULL, defaults to 0.0.0.0 */
    *port;            /* port to listen on; if NULL, defaults to `ZT_DEFAULT_LISTEN_PORT` */
  int
    sockfd;           /* listening socket file descriptor */
    clientfd;         /* client socket file descriptor */
    sock_flags;       /* original socket flags */
    send_timeout;     /* send timeout (ms) */
    recv_timeout;     /* recv timeout (ms) */
  bool
    fl_tcp_fastopen;  /* enable TCP Fast Open (RFC 7413) on the listening socket */
    fl_live_read;     /* enable live read mode */
} zt_server_connection_t;
// clang-format on

#endif /* __SERVER_H__ */
