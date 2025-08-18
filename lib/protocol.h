// [CAUTION] sample protocol.h for testing until the build system is in place

#pragma once

// clang-format off

/**
 * handshake_protocol_t:
 * - KAPPA_UNKNOWN: unknown version
 * - KAPPAv1_unstable: KAPPA version 1 (unstable)
 *
 * Enumeration of handshake protocol versions (stable/unstable).
 * Must be listed in increasing chronological order.
 */
typedef enum {
  KAPPAv1_unstable        = 1,
  KAPPA_UNKNOWN           = 0xff,
} handshake_protocol_t;

#define HANDSHAKE_PROTOCOL_VERSION KAPPAv1_unstable

handshake_protocol_t get_handshake_protocol_version(void) {
  return (handshake_protocol_t)HANDSHAKE_PROTOCOL_VERSION;
}

int handshake_protocol_version_at_least(handshake_protocol_t version) {
  return version != KAPPA_UNKNOWN && get_handshake_protocol_version() >= version;
}
