/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * protocol.in.h
 */

#pragma once

// clang-format off

/**
 * handshake_protocol_t:
 * - KAPPA_UNKNOWN: unknown version
 * - KAPPAv1_unstable: KAPPA version 1 (unstable)
 *
 * Enumeration of handshake protocol versions (stable/unstable).
 * Must be listed in increasing chronological order.
 *
 * WARNING: Do not edit this enum, the build system will use
 *          protocol versions in numeric form.
 */
typedef enum {
  KAPPAv1_unstable        = 1,
  KAPPA_UNKNOWN           = 0xff,
} handshake_protocol_t;

#cmakedefine HANDSHAKE_PROTOCOL_VERSION @HANDSHAKE_PROTOCOL_VERSION@

handshake_protocol_t get_handshake_protocol_version(void) {
  return (handshake_protocol_t)HANDSHAKE_PROTOCOL_VERSION;
}

int handshake_protocol_version_at_least(handshake_protocol_t version) {
  return version != KAPPA_UNKNOWN && get_handshake_protocol_version() >= version;
}
