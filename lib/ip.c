/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * ip.c
 */

#include "ip.h"

#include <arpa/inet.h>
#include <netinet/in.h>

bool zt_check_ip_family(const char *ip, int family) {
  char buf[sizeof(struct in6_addr)];

  if (!ip)
    return false;

  if (inet_pton(family, ip, buf) == 1)
    return true;
  return false;
}

int zt_choose_ip_family(bool use_ipv4, bool use_ipv6) {
  if (use_ipv4 && use_ipv6)
    return AF_UNSPEC; /* both IPv4 and IPv6 */
  else if (use_ipv4)
    return AF_INET; /* only IPv4 */
  else if (use_ipv6)
    return AF_INET6; /* only IPv6 */
  else
    return -1;
}