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
  const char
    *hostname,
    *port;
  struct authid
    authid_mine,   /* local AuthId */
    authid_peer;   /* peer's AuthId */
  passwd_id_t
    renegotiation_passwd;
  int
    sockfd,
    sock_flags,
    connect_timeout,
    send_timeout,
    recv_timeout;
  bool
    first_send,
    renegotiation;
  bool
    fl_tcp_fastopen   : 1,  /* is TCP fastopen enabled */
    fl_tcp_nodelay    : 1,  /* is TCP_NODELAY enabled */
    fl_explicit_port  : 1,  /* override default service port */
    fl_live_read      : 1;  /* is live read enabled */
} zt_client_connection_t;
// clang-format on

/**
 * Initialize memory for the client.
 *
 * @param[out] conn Pointer to store the client connection context.
 * @return An `err_t` status code.
 *
 * @note This function will allocate resources depending on the features
 * enabled as indicated by global config variable `g_config`. Make sure
 * the global configuration is set before calling this function.
 */
err_t zt_client_conn_alloc(zt_client_connection_t **conn);

/**
 * Deallocate the alloc'ed client connection context.
 *
 * @param[in] conn The client connection context to free.
 * @return Void.
 *
 * Free the the memory associated with the client connection context pointed to
 * by @p conn.
 */
void zt_client_conn_dealloc(zt_client_connection_t *conn);

/**
 * Run the client connection.
 *
 * @param[in] conn The alloc'ed client connection context.
 * @param[in] args Additional arguments.
 * @param[out] done Set to True if the transfer completed successfully.
 *
 * @p *bool is set to True if the transfer completed successfully.
 *
 * @return An `err_t` status code.
 */
err_t zt_client_run(zt_client_connection_t *conn, void *args, bool *done);

int zt_client_tcp_send(zt_client_connection_t *conn, const uint8_t *buf,
                       size_t nbytes);

ssize_t zt_client_tcp_recv(zt_client_connection_t *conn, uint8_t *buf,
                           size_t nbytes, bool *pending);

/**
 * Enable/disable TCP_FASTOPEN for the client connection
 *
 * @param[in] conn The alloc'ed client connection context.
 * @param[in] enable True to enable, False to disable.
 * @return An `err_t` status code.
 */
err_t zt_client_enable_tcp_fastopen(zt_client_connection_t *conn, bool enable);

/**
 * Enable/disable TCP_NODELAY for the client connection
 *
 * @param[in] conn The alloc'ed client connection context.
 * @param[in] enable True to enable, False to disable.
 * @return An `err_t` status code.
 */
err_t zt_client_enable_tcp_nodelay(zt_client_connection_t *conn, bool enable);

/**
 * Enable/disable explicit port for the client connection
 *
 * @param[in] conn The alloc'ed client connection context.
 * @param[in] enable True to enable, False to disable.
 * @return An `err_t` status code.
 */
err_t zt_client_enable_explicit_port(zt_client_connection_t *conn, bool enable);

/**
 * Enable/disable live read for the client connection
 *
 * @param[in] conn The alloc'ed client connection context.
 * @param[in] enable True to enable, False to disable.
 * @return An `err_t` status code.
 */
err_t zt_client_enable_live_read(zt_client_connection_t *conn, bool enable);

#endif /* __CLIENT_H__ */
