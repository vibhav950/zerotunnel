#ifndef __CONN_DEFS_H__
#define __CONN_DEFS_H__

#include "common/defines.h"
#include "io.h"

#include <sys/socket.h>

/* TCP socket writability */
#define ZT_NETIO_WRITABLE               ZT_IO_READABLE
/* TCP socket readability */
#define ZT_NETIO_READABLE               ZT_IO_WRITABLE

/**
 * Default port numbers
 */

#define ZT_DEFAULT_LISTEN_PORT          "9595"   /* Default service port */

/**
 * Timeouts waiting periods
 */

#define ZT_CLIENT_TIMEOUT_RESOLVE       10000U  /* Host resolution timeout (msec) */
#define ZT_CLIENT_TIMEOUT_CONNECT       10000U  /* Client connect timeout (msec) */
#define ZT_CLIENT_TIMEOUT_SEND          5000U   /* Client send() timeout (msec) */
#define ZT_CLIENT_TIMEOUT_RECV          5000U   /* Client recv() timeout (msec) */

#define ZT_CLIENT_TIMEOUT_SEND_DEFAULT  5000U   /* Server send() timeout (msec) */
#define ZT_CLIENT_TIMEOUT_RECV_DEFAULT  5000U   /* Server recv() timeout (msec) */

#define CLIENT_RESOLVE_RETRIES          5       /* Max host resolution retries */

#define MAX_AUTH_RETRY_COUNT            3       /* Max authentication retries */

enum {
  MSG_HANDSHAKE   = (1 << 0), /* Crypto handshake message */
  MSG_AUTH_RETRY  = (1 << 1), /* Authentication retry message */
  MSG_CONTROL     = (1 << 2), /* Control message */
  MSG_METADATA    = (1 << 3), /* File metadata message */
  MSG_FILEDATA    = (1 << 4), /* File payload message */
  MSG_DONE        = (1 << 5), /* No further messages pending */
  MSG_ANY         = 0xff,
};

typedef uint8_t zt_msg_type_t;

/** message data end marker */
#define MSG_END                                 0x01

/** message flow termination marker */
#define DONE_MARKER                             "BYE"

/** size of message header */
#define ZT_MSG_HEADER_SIZE                      (sizeof(zt_msg_type_t) + sizeof(uint32_t))

/** size of msg suffix */
#define ZT_MSG_SUFFIX_SIZE                      32UL

/** size of max `msg.data[]` */
#define ZT_MAX_TRANSFER_SIZE                    (1UL << 17)

/** size of `msg.raw[]` */
#define ZT_MSG_MAX_RAW_SIZE                     (ZT_MSG_HEADER_SIZE + ZT_MAX_TRANSFER_SIZE + ZT_MSG_SUFFIX_SIZE + 1)

typedef struct _zt_msg_st {
  union {
    struct {
      zt_msg_type_t type;                     /* Message type */
      uint32_t len;                           /* Length of `data[]` */
      uint8_t data[ZT_MAX_TRANSFER_SIZE + 1]; /* Message payload */
    };
    /* Raw data (`type` || `len` || `data[]` || <suffix>) */
    uint8_t raw[ZT_MSG_MAX_RAW_SIZE];
  };
} zt_msg_t;

/** `msg.data[]` pointer */
#define zt_msg_data_ptr(msgptr)                 ((uint8_t *)(msgptr)->data)

/** `msg.raw[]` pointer */
#define zt_msg_raw_ptr(msgptr)                  ((uint8_t *)(msgptr)->raw)

/** length of `msg.data[]` */
#define zt_msg_data_len(msgptr)                 (ntoh32((msgptr)->len))

/** msg type */
#define zt_msg_type(msgptr)                     ((msgptr)->type)

/** set `msg.len` */
#define zt_msg_set_len(msgptr, len_val)         (void)(msgptr->len = hton32(len_val))

/** set `msg.type` */
#define zt_msg_set_type(msgptr, type_val)       (void)(msgptr->type = (type_val))

/** Populate message `msgptr` */
#define zt_msg_make(msgptr, type, data, len)                                   \
  do {                                                                         \
    zt_memcpy(zt_msg_data_ptr(msgptr), data, len);                             \
    zt_msg_set_type(msgptr, type);                                             \
    zt_msg_set_len(msgptr, len);                                               \
  } while (0)

/** check message type validity */
static inline bool msg_type_isvalid(zt_msg_type_t type) {
  return (type >= MSG_HANDSHAKE && type <= MSG_DONE);
}

struct zt_addrinfo {
  int                   ai_flags;
  int                   ai_family;
  int                   ai_socktype;
  int                   ai_protocol;
  socklen_t             ai_addrlen;
  char                  *ai_canonname;
  struct sockaddr       *ai_addr;
  struct zt_addrinfo    *ai_next;
  size_t                total_size;
};

void zt_addrinfo_free(struct zt_addrinfo *ai);

void zt_addrinfo_set_port(struct zt_addrinfo *ai, int port);

int zt_tcp_io_waitfor(int sockfd, timediff_t timeout_msec, int mode);

bool zt_tcp_io_waitfor_read(int sockfd, timediff_t timeout_msec);

bool zt_tcp_io_waitfor_write(int sockfd, timediff_t timeout_msec);

#endif /* __CONN_DEFS_H__ */
