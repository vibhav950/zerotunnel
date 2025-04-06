#ifndef __CONN_DEFS_H__
#define __CONN_DEFS_H__

#include "common/defines.h"
#include "client.h"
#include "io.h"

#include <sys/socket.h>

/* TCP socket writability */
#define ZT_NETIO_WRITABLE               ZT_IO_READABLE
/* TCP socket readability */
#define ZT_NETIO_READABLE               ZT_IO_WRITABLE

/**
 * Size of the biggest I/O buffer
 * Note: ZT_TCP_MAX_CHUNK_SIZE <= ZT_MAX_IO_TRANSFER_SIZE
 */
#define ZT_MAX_TRANSFER_SIZE            (1UL << 17)

/* Size of the largest payload chunk */
#define ZT_TCP_MAX_CHUNK_SIZE           ZT_IO_MAX_CHUNK_SIZE

/**
 * Default port numbers
 */
#define ZT_DEFAULT_LISTEN_PORT          9595   /* Default service port */

/**
 * Timeouts waiting periods
 */
#define ZT_CLIENT_TIMEOUT_RESOLVE       30000U  /* Host resolution timeout (msec) */
#define ZT_CLIENT_TIMEOUT_CONNECT       30000U  /* Client connect timeout (msec) */
#define ZT_CLIENT_TIMEOUT_SEND          15000U  /* Client send() timeout (msec) */
#define ZT_CLIENT_TIMEOUT_RECV          15000U  /* Client recv() timeout (msec) */

// #define SERVER_TIMEOUT_COMMIT   30U  /* Client commitment timeout (sec) */
// #define SERVER_TIMEOUT_TRANSFER 30U  /* Timeout to abort ongoing transfer (sec) */


#define CLIENT_RESOLVE_RETRIES          5   /* Host resolution retries */

typedef enum {
  MSG_HANDSHAKE   = (1 << 0), /* Handshake message type */
  MSG_CONTROL     = (1 << 1), /* Control message */
  MSG_METADATA    = (1 << 2), /* File metadata */
  MSG_DATA        = (1 << 3), /* Session payload */
  MSG_DONE        = (1 << 4), /* No further messages sent from now */
} ZT_MSG_TYPE;

typedef struct _zt_msg_st {
  union {
    struct {
      uint32_t type;                            /* Message type */
      uint8_t  data[ZT_MAX_TRANSFER_SIZE + 32]; /* Message payload */
    };
    uint8_t  raw[ZT_MAX_TRANSFER_SIZE + 64];    /* Raw data (`type` || `data[]`) */
  };
  size_t len;                                   /* Length of `data[]` */
} zt_msg_t;

static inline ATTRIBUTE_ALWAYS_INLINE void
zt_msg_make(zt_msg_t *msg, ZT_MSG_TYPE type, size_t len) {
  ASSERT((len > 0) && (len <= ZT_MAX_TRANSFER_SIZE));
  msg->type = type;
  msg->len = len;
}

#define zt_msg_data_ptr(msgptr)                 ((uint8_t *)(msgptr)->data)
#define zt_msg_raw_ptr(msgptr)                  ((uint8_t *)(msgptr)->raw)
#define zt_msg_data_len(msgptr)                 ((msgptr)->len)
#define zt_msg_type(msgptr)                     ((msgptr)->type)
#define zt_msg_set_len(msgptr, len_val)         ((void)((msgptr) && (msgptr->len = (len_val))))
#define zt_msg_set_type(msgptr, type_val)       ((void)((msgptr) && (msgptr->type = (type_val))))

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

int zt_tcp_io_waitfor(int sockfd, timediff_t timeout_msec, int mode);

bool zt_tcp_io_waitfor_read(int sockfd, timediff_t timeout_msec);

bool zt_tcp_io_waitfor_write(int sockfd, timediff_t timeout_msec);

int zt_client_tcp_send(zt_client_connection_t *conn, const uint8_t *buf,
                       size_t nbytes);

ssize_t zt_client_tcp_recv(zt_client_connection_t *conn, uint8_t *buf,
                           size_t nbytes, bool *pending);

#endif /* __CONN_DEFS_H__ */
