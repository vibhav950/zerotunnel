/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * ztver.h - zerotunnel version definitions
 */

#ifndef __ZTVER_H__
#define __ZTVER_H__

#define ZT_VERSION_MAJOR 1 /* incompatible API changes */
#define ZT_VERSION_MINOR 0 /* backward compatible changes */
#define ZT_VERSION_PATCH 1 /* backword compatible fixes/improvements */

/**
 * A numeric representation of the Zerotunnel version number, simplifying
 * version comparisons for internal use and for external programs.
 *
 * The 6-digit (24 bits) hexadecimal version number is represented in the
 * following format 0xMMmmPP, where:
 *   - MM is the major version number (8 bits)
 *   - mm is the minor version number (8 bits)
 *   - PP is the patch version number (8 bits)
 *
 * For example, version 1.0.255 would be represented as 0x0100FF.
 */
#define ZT_VERSION_NUMBER 0x010001

/**
 * The Zerotunnel version string in the format "MM.mm.PP", where:
 *  - MM is the major version number
 *  - mm is the minor version number
 *  - PP is the patch version number
 *
 * Note: This string format will not include any pre-release or build meta tags.
 */
#define ZT_VERSION_STRING "1.0.1"

/**
 * Convert a version number in the (major, minor, patch) representation to a
 * 6-digit (24 bits) hexadecimal number in the format 0xMMmmPP.
 */
#define ZT_VERSION_TO_NUMERIC(major, minor, patch)                                       \
  (((major) << 16) | ((minor) << 8) | (patch))

/**
 * Convert a version number in the (major, minor, patch) representation to a
 * string in the format "MM.mm.PP".
 */
#define ZT_VERSION_TO_STRING(major, minor, patch) #major "." #minor "." #patch

/**
 * A macro to check if the current Zerotunnel version is at least the version
 * specified in the (major, minor, patch) format.
 */
#define ZT_VERSION_AT_LEAST(major, minor, patch)                                         \
  (ZT_VERSION_NUMBER >= ZT_VERSION_TO_NUMERIC(major, minor, patch))

#endif /* __ZTVER_H__ */
