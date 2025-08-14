#pragma once

#include "auth.h"
#include "client.h"
#include "common/defines.h"

#include <stdbool.h>

// clang-format off
struct config {
  char
    *hostname,
    *passwddb_file,
    *ciphersuite,
    *filename;
  uint32_t
    padding_factor;     /* padding factor of the form: 2^n; 1<=n<=16 */
  uint16_t
    port;               /* explicit service port number */
  char
    preferred_family;   /* preferred address family: '4' for IPv4, '6' for IPv6 */
  short
    password_size;      /* number of chars or words in password */
  int
    connect_timeout,    /* positive timeout for connection */
    idle_timeout,       /* positive timeout for server being idle */
    recv_timeout,       /* positive timeout for receiving data */
    send_timeout;       /* positive timeout for sending data */
  auth_type_t
    auth_type;
  char
    flag_explicit_port,
    flag_ipv4_only,
    flag_ipv6_only,
    flag_length_obfuscation,
    flag_live_read,
    flag_lz4_compression,
    flag_tcp_nodelay,
    flag_tcp_fastopen;
};
