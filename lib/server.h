#ifndef __SERVER_H__
#define __SERVER_H__

#include "auth.h"
#include "ciphersuites.h"
#include "conn_defs.h"
#include "io.h"

#include <netinet/in.h>
#include <sys/socket.h>

typedef enum {
  SERVER_NONE = 0,
  SERVER_CONN_INIT,
  SERVER_CONN_LISTEN,
  SERVER_AUTH_RESPOND,
  SERVER_AUTH_COMPLETE,
  SERVER_COMMIT,
  SERVER_TRANSFER,
  SERVER_DONE
} ZT_SERVER_STATE;

// clang-format off
typedef struct _zt_server_connection_st {
  ZT_SERVER_STATE
    state;
  struct {
#ifdef HAVE_IPV6
    char ip[INET6_ADDRSTRLEN];      /* server address */
#else
    char ip[INET_ADDRSTRLEN];       /* server address */
#endif
    char port[6];                   /* server port */
    struct authid authid;           /* local AuthId */
  } self;
  struct {
    socklen_t addrlen;
    struct sockaddr_storage addr;
#ifdef HAVE_IPV6
    char ip[INET6_ADDRSTRLEN];      /* client address */
#else
    char ip[INET_ADDRSTRLEN];       /* client address */
#endif
    char port[6];                   /* client port */
    struct authid authid;           /* peer AuthId */
    int
      fd,                           /* client socket file descriptor */
      fd_flags;                     /* restore client socket flags */
  } peer;
  struct zt_addrinfo
    *ai_estab;                      /* established address */
  zt_msg_t
    *msgbuf;                        /* message buffer */
  const char
    *hostname,                      /* stated hostname string; if NULL, defaults to 0.0.0.0 */
    *listen_port;                   /* stated port string; if NULL, defaults to ZT_DEFAULT_LISTEN_PORT */
  ciphersuite_t
    ciphersuite;                    /* negotiated ciphersuite */
  struct {
    bool expect;                    /* expecting a passwd renegotiation */
    passwd_id_t id;                 /* expected passwd Id after renegotiation */
  } expected_passwd;
  zt_fileinfo_t
    fileinfo;                       /* file information */
  int
    auth_retries;                   /* number of handshake retries (=0 on first attempt) */
  int
    sockfd,                         /* listening socket file descriptor */
    sockfd_flags,                   /* restore listener socket flags */
    idle_timeout,                   /* server idle timeout (ms) */
    send_timeout,                   /* send timeout (ms) */
    recv_timeout;                   /* recv timeout (ms) */
  bool
    fl_tcp_fastopen,                /* enable TCP Fast Open (RFC 7413) on the listening socket */
    fl_tcp_nodelay,                 /* enable TCP_NODELAY on the listening socket */
    fl_explicit_port,               /* override default service port */
    fl_pending,                     /* unprocessed message in buffer */
    fl_live_read;                   /* ongoing live read */
} zt_server_connection_t;
// clang-format on

/**
 * Initialize memory for the server
 *
 * @param[out] conn Pointer to store the server connection context.
 * @return An `err_t` status code.
 *
 * @note This function will allocate resources depending on the features
 * enabled as indicated by global config variable `GlobalConfig`. Make sure
 * the global configuration is set before calling this function.
 */
err_t zt_server_conn_alloc(zt_server_connection_t **conn);

/**
 * Deallocate the alloc'ed server connection context.
 *
 * @param[in] conn The server connection context to free.
 * @return Void.
 *
 * Free the the memory associated with the server connection context pointed to
 * by @p conn.
 */
void zt_server_conn_dealloc(zt_server_connection_t *conn);

/**
 * Run the server connection.
 *
 * @param[in] conn The alloc'ed server connection context.
 * @param[in] args Additional arguments.
 *
 * @p *bool is set to True if the transfer completed successfully.
 *
 * @return An `err_t` status code.
 */
err_t zt_server_run(zt_server_connection_t *conn, void *args, bool *done);

int zt_server_tcp_send(zt_server_connection_t *conn, const uint8_t *buf, size_t nbytes);

ssize_t zt_server_tcp_recv(zt_server_connection_t *conn, uint8_t *buf, size_t nbytes,
                           bool *pending);

/**
 * Enable/disable TCP_FASTOPEN for the server connection
 *
 * @param[in] conn The alloc'ed server connection context.
 * @param[in] enable True to enable, False to disable.
 * @return An `err_t` status code.
 */
err_t zt_server_enable_tcp_fastopen(zt_server_connection_t *conn, bool enable);

/**
 * Enable/disable TCP_NODELAY for the server connection
 *
 * @param[in] conn The alloc'ed server connection context.
 * @param[in] enable True to enable, False to disable.
 * @return An `err_t` status code.
 */
err_t zt_server_enable_tcp_nodelay(zt_server_connection_t *conn, bool enable);

/**
 * Enable/disable explicit port for the server connection
 *
 * @param[in] conn The alloc'ed server connection context.
 * @param[in] enable True to enable, False to disable.
 * @return An `err_t` status code.
 */
err_t zt_server_enable_explicit_port(zt_server_connection_t *conn, bool enable);

#endif /* __SERVER_H__ */
