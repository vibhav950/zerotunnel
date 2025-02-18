#ifndef __CONN_DEFS_H__
#define __CONN_DEFS_H__

/**
 * Default port numbers
 */
#define SERVICE_PORT_SECFTP             9595   /* Port for this service */

/**
 * Timeouts waiting periods
 */
#define ZT_CLIENT_TIMEOUT_RESOLVE       30000U  /* Host resolution timeout (msec) */
#define ZT_CLIENT_TIMEOUT_CONNECT       30000U  /* Client connect timeout (msec) */
#define ZT_CLIENT_TIMEOUT_LIBC_SEND     15000U  /* Client send(2) timeout (msec) */
#define ZT_CLIENT_TIMEOUT_LIBC_RECV     15000U  /* Client receive(2) timeout (msec) */

// #define SERVER_TIMEOUT_COMMIT   30U  /* Client commitment timeout (sec) */
// #define SERVER_TIMEOUT_TRANSFER 30U  /* Timeout to abort ongoing transfer (sec) */


#define CLIENT_RESOLVE_RETRIES       5   /* Host resolution retries */

#include <sys/socket.h>

struct zt_addrinfo {
  int                   ai_flags;
  int                   ai_family;
  int                   ai_socktype;
  int                   ai_protocol;
  socklen_t             ai_addrlen;
  char                  *ai_canonname;
  struct sockaddr       *ai_addr;
  struct zt_addrinfo    *ai_next;
};

void zt_addrinfo_free(struct zt_addrinfo *ai);

void zt_addrinfo_set_port(struct zt_addrinfo *ai, int port);

#endif // __CONN_DEFS_H__
