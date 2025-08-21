#ifndef __CONN_DEFS_H__
#define __CONN_DEFS_H__

#include "common/defines.h"
#include "io.h"
#include "lz4.h"

#include <sys/socket.h>

// clang-format off

/* TCP socket writability */
#define ZT_NETIO_WRITABLE               ZT_IO_READABLE
/* TCP socket readability */
#define ZT_NETIO_READABLE               ZT_IO_WRITABLE

/**
 * Default port numbers
 */

#define ZT_DEFAULT_LISTEN_PORT          "9500"   /* Default service port */

/**
 * Timeouts waiting periods
 */

#define ZT_CLIENT_TIMEOUT_CONNECT_DEFAULT       15000U    /* Client connect timeout (msec) */
#define ZT_CLIENT_TIMEOUT_SEND_DEFAULT          120000U   /* Client send() timeout (msec) */
#define ZT_CLIENT_TIMEOUT_RECV_DEFAULT          120000U   /* Client recv() timeout (msec) */

#define ZT_SERVER_TIMEOUT_IDLE_DEFAULT          120000U   /* Server idle timeout (msec) */
#define ZT_SERVER_TIMEOUT_SEND_DEFAULT          120000U   /* Server send() timeout (msec) */
#define ZT_SERVER_TIMEOUT_RECV_DEFAULT          120000U   /* Server recv() timeout (msec) */

#define ZT_CLIENT_RESOLVE_RETRY_INTERVAL        1000U     /* Client resolve retry interval (msec) */

#define ZT_CLIENT_RESOLVE_RETRIES               8         /* Max host resolution retries */

#define ZT_MAX_AUTH_RETRY_COUNT                 3         /* Max authentication retries */

#define ZT_DEFAULT_CIPHER_SUITE_ID              0x01      /* Default ciphersuite */

enum {
  MSG_HANDSHAKE       = (1 << 0), /* Crypto handshake message */
  MSG_AUTH_RETRY      = (1 << 1), /* Authentication retry message */
  MSG_HANDSHAKE_FIN   = (1 << 2), /* Final handshake message */
  MSG_CONTROL         = (1 << 3), /* Control message */
  MSG_METADATA        = (1 << 4), /* File metadata message */
  MSG_FILEDATA        = (1 << 5), /* File payload message */
  MSG_DONE            = (1 << 6), /* No further messages pending */
  MSG_ANY             = 0xff,
};

enum {
  MSG_FL_COMPRESSION = (1 << 0), /* Message is compressed */
  MSG_FL_PADDING     = (1 << 1), /* Message is padded */
};

typedef uint8_t zt_msg_type_t;
typedef uint16_t zt_msg_flags_t;

/** Message data end marker */
#define MSG_END_BYTE                            0x01

/** Message flow termination marker */
// #define DONE_MSG_UTF8                           "BYE"

/** Size of message header */
#define ZT_MSG_HEADER_SIZE                                                     \
  (sizeof(zt_msg_type_t) + sizeof(uint32_t) + sizeof(zt_msg_flags_t))

/** Size of msg suffix */
#define ZT_MSG_SUFFIX_SIZE                      32UL

/** Max size of usable data in `msg.data[]` */
#define ZT_MSG_MAX_RW_SIZE                      (1UL << 16) /* 64K Bytes */

/** Size of `msg.raw[]` */
#define ZT_MSG_MAX_RAW_SIZE                                                    \
  (ZT_MSG_HEADER_SIZE + ZT_MSG_SUFFIX_SIZE + ZT_MSG_MAX_RW_SIZE + 1)

/** Size of `msg._xbuf[]` */
#define ZT_MSG_XBUF_SIZE                                                       \
  (ZT_MSG_HEADER_SIZE + ZT_MSG_SUFFIX_SIZE +                                   \
   LZ4_COMPRESSBOUND(ZT_MSG_MAX_RW_SIZE + 1))

#pragma pack(push, 1)
typedef struct _zt_msg_st {
  union {
    struct {
      zt_msg_type_t type;                   /* Message type */
      uint32_t len;                         /* Length of `data[]` */
      zt_msg_flags_t flags;                 /* Message flags */
      uint8_t data[ZT_MSG_MAX_RW_SIZE + 1]; /* Message payload */
    };
    /* Raw data (`type` || `len` || `data[]` || <suffix>) */
    uint8_t raw[ZT_MSG_MAX_RAW_SIZE];
  };
  uint8_t *_xbuf;
} zt_msg_t;
#pragma pack(pop)

/** `msg.data[]` pointer */
#define MSG_DATA_PTR(msgptr)                    ((msgptr)->data)

/** `msg.raw[]` pointer */
#define MSG_RAW_PTR(msgptr)                     ((msgptr)->raw)

/** `msg._xbuf[]` pointer */
#define MSG_XBUF_PTR(msgptr)                    ((msgptr)->_xbuf)

/** Get `msg.len` */
#define MSG_DATA_LEN(msgptr)                    (ntoh32((msgptr)->len))

/** Get `msg.type` */
#define MSG_TYPE(msgptr)                        ((msgptr)->type)

/** Get `msg.flags` */
#define MSG_FLAGS(msgptr)                       (ntoh16((msgptr)->flags))

/** Set `msg.len` */
#define MSG_SET_LEN(msgptr, len_val)            (void)((msgptr)->len = hton32(len_val))

/** Set `msg.type` */
#define MSG_SET_TYPE(msgptr, type_val)          (void)((msgptr)->type = (type_val))

/** Set `msg.flags` */
#define MSG_SET_FLAGS(msgptr, setflags)         (void)((msgptr)->flags = hton16(setflags))

/** Populate message `msgptr` */
#define MSG_MAKE(msgptr, type, data, len, setflags)                            \
  do {                                                                         \
    if (len)                                                                   \
      memcpy(MSG_DATA_PTR(msgptr), data, len);                                 \
    MSG_SET_TYPE(msgptr, type);                                                \
    MSG_SET_LEN(msgptr, len);                                                  \
    MSG_SET_FLAGS(msgptr, setflags);                                           \
  } while (0)

/** Check message type validity */
static inline bool msg_type_isvalid(zt_msg_type_t type) {
  return type >= MSG_HANDSHAKE && type <= MSG_DONE;
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
