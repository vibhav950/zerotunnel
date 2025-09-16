/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * zt_addrinfo.c
 */

#include "common/defines.h"
#include "conn_defs.h"

#include <arpa/inet.h>

void zt_addrinfo_free(struct zt_addrinfo *ai) {
  struct zt_addrinfo *ai_cur, *ai_next;

  for (ai_cur = ai; ai_cur; ai_cur = ai_next) {
    ai_next = ai_cur->ai_next;
    zt_free(ai_cur);
  }
}

void zt_addrinfo_set_port(struct zt_addrinfo *ai, int port) {
  struct zt_addrinfo *ai_cur;
  struct sockaddr_in *addr;
#ifdef HAVE_IPV6
  struct sockaddr_in6 *addr6;
#endif

  ASSERT(ai);
  ASSERT(port > 0);

  for (ai_cur = ai; ai_cur; ai_cur = ai_cur->ai_next) {
    switch (ai_cur->ai_family) {
    case AF_INET:
      addr = (struct sockaddr_in *)ai_cur->ai_addr;
      addr->sin_port = htons((unsigned short)port);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      addr6 = (struct sockaddr_in6 *)ai_cur->ai_addr;
      addr6->sin6_port = htons((unsigned short)port);
      break;
#endif
    }
  }
}
