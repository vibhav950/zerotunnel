#pragma once

#include "auth.h"
#include "client.h"
#include "common/defines.h"

#include <stdbool.h>

// clang-format off
struct config {
  char
    *hostname,                  /* peer hostname -- can be a FQDN or IP address */
    *passwdfile,                /* location of the password database file */
    *ciphersuite,               /* ciphersuite cannonical name or alias */
    *filepath,                  /* complete target file path */
    *passwd_bundle_id;          /* bundle identifier for KAPPA1 auth type */
  uint32_t
    padding_factor;             /* padding factor of the form: 2^n; 1<=n<=16 */
  uint16_t
    service_port;               /* explicit service port number */
  char
    preferred_family;           /* preferred address family: '4' for IPv4, '6' for IPv6 */
  int
    password_bundle_size,       /* number of passwords in a bundle */
    password_chars,             /* number of UTF-8 chars in a password */
    password_words;             /* number of words in a phonetic password */
  int
    connect_timeout,            /* timeout for connection phase (>0 ms) */
    idle_timeout,               /* timeout for server being idle (>0 ms) */
    recv_timeout,               /* timeout for receiving data (>0 ms) */
    send_timeout;               /* timeout for sending data (>0 ms) */
  auth_type_t
    auth_type;                  /* KAPPA authentication type */
  char
    flag_explicit_port,         /* use an explicit service port */
    flag_ipv4_only,             /* use IPv4 only */
    flag_ipv6_only,             /* use IPv6 only */
    flag_length_obfuscation,    /* enable length obfuscation */
    flag_live_read,             /* enable live read */
    flag_lz4_compression,       /* enable LZ4 compression */
    flag_tcp_fastopen,          /* enable TCP_FASTOPEN */
    flag_tcp_nodelay;           /* enable TCP_NODELAY */
};

/** Global configuration options for use within the library */
extern struct config GlobalConfig;
