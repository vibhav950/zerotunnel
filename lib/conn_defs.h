#ifndef __CONN_DEFS_H__
#define __CONN_DEFS_H__

/**
 * Default port numbers
 */
#define SERVICE_PORT_SECFTP          9595   /* Port for this service */

/**
 * Timeouts waiting periods
 */
#define CLIENT_TIMEOUT_RESOLVE       30000U  /* Host resolution timeout (msec) */
#define CLIENT_TIMEOUT_CONNECT       30000U  /* Client connect timeout (msec) */
#define CLIENT_TIMEOUT_LIBC_SEND     15000U  /* Client send(2) timeout (msec) */
#define CLIENT_TIMEOUT_LIBC_RECV     15000U  /* Client receive(2) timeout (msec) */

// #define SERVER_TIMEOUT_COMMIT   30U  /* Client commitment timeout (sec) */
// #define SERVER_TIMEOUT_TRANSFER 30U  /* Timeout to abort ongoing transfer (sec) */


#define CLIENT_RESOLVE_RETRIES       5   /* Host resolution retries */

#include <sys/socket.h>

struct my_addrinfo {
  int                   ai_flags;
  int                   ai_family;
  int                   ai_socktype;
  int                   ai_protocol;
  socklen_t             ai_addrlen;
  char                  *ai_canonname;
  struct sockaddr       *ai_addr;
  struct my_addrinfo    *ai_next;
};

#endif // __CONN_DEFS_H__
