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
    *peer_id,
    *ciphersuite,
    *filename;
  uint16_t
    padding_factor; // ignored unless `config_length_obfuscation=true`
  uint32_t
    port; // ignored unless `config_explicit_port=true`
  auth_type_t
    auth_type;
  bool
    config_explicit_port : 1,
    config_ipv6 : 1,
    config_live_read : 1,
    config_length_obfuscation : 1,
    config_port : 1,
    config_tcp_nodelay : 1,
    config_tcp_fastopen : 1,
    connect_timeout : 1,
    recv_timeout : 1,
    resolve_timeout : 1,
    send_timeout : 1,
    tcp_fastopen : 1;
} config;