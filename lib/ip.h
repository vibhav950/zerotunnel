#pragma once

#include <stdbool.h>

/**
 * Check if the given IP address is of the specified family.
 *
 * @param[in] ip The IP address string to check.
 * @param[in] family The address family (AF_INET for IPv4, AF_INET6 for IPv6).
 * @return true if the IP address matches the specified family, false otherwise.
 */
bool zt_check_ip_family(const char *ip, int family);

/**
 * Choose the appropriate IP family based on the flags.
 *
 * @param[in] use_ipv4 True if IPv4 can be used.
 * @param[in] use_ipv6 True if IPv6 can be used.
 * @return The chosen address family (AF_INET, AF_INET6, or AF_UNSPEC),
 *         or -1 if both @p use_ipv4 and @p use_ipv6 are false.
 */
int zt_choose_ip_family(bool use_ipv4, bool use_ipv6);
