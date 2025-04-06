#pragma once

#include "auth.h"
#include "client.h"
#include "common/defines.h"

#include <stdbool.h>

struct _config {
  char
    *addr_ipv4,
    *addr_ipv6,
    *hostname,
    *passwddb_file,
    *peer_id, // an optional name for the peer
    *cipher_alg,
    *aead_alg,
    *hmac_alg,
    *ecdh_alg,
    *kem_alg,
    *kdf_alg;
  auth_type_t
    auth_type;
  struct authid
    authid_mine,
    authid_peer;
  bool
    config_ipv6 : 1,
    config_live_read : 1,
    config_port : 1,
    config_tcp_nodelay : 1,
    config_tcp_fastopen : 1,
    connect_timeout : 1,
    port : 1,
    recv_timeout : 1,
    resolve_timeout : 1,
    send_timeout : 1,
    tcp_fastopen : 1;
} config;