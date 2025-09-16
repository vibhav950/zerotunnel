/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * systemrand.h
 */

#ifndef __SYSTEMRAND_H__
#define __SYSTEMRAND_H__

#include "rdrand.h"

#include <stddef.h>

/**
 * Securely generate \p bytes random bytes into \p.
 */
void zt_systemrand_bytes(uint8_t *buf, size_t bytes);

/**
 * Securely generate \p bytes4 4-byte random words into \p buf.
 */
void zt_systemrand_4bytes(uint32_t *buf, size_t bytes4);

/**
 * Securely generate \p bytes8 8-byte random words into \p buf.
 */
void zt_systemrand_8bytes(uint64_t *buf, size_t bytes8);

/**
 * Returns a 8-bit random value.
 */
uint8_t zt_rand_u8(void);

/**
 * Returns a 16-bit random value.
 */
uint16_t zt_rand_u16(void);

/**
 * Returns a 32-bit random value.
 */
uint32_t zt_rand_u32(void);

/**
 * Returns a 64-bit random value.
 */
uint64_t zt_rand_u64(void);

/**
 * Returns a random integer in the range [0, max], max > 0.
 */
int64_t zt_rand_ranged(int64_t max);

static const char RAND_DEFAULT_CHARSET[] = "abcdefghijklmnopqrstuvwxyz"
                                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                           "0123456789"
                                           "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/**
 * Generate a sequence of random readable characters and place it in \p rstr.
 *
 * \param rstr Buffer for the random string.
 * \param rstr_len Length of \p rstr INCLUDING the null terminator.
 * \param charset A null-terminated string containing the UTF-8 character set.
 * If null is passed, then RAND_DEFAULT_CHARSET is used as the character set.
 * \param charset_len Length of \p charset EXCLUDING the null terminator (must
 * be zero if \p charset is null).
 *
 * \return 0 on success, -1 on error.
 */
int zt_rand_charset(char *rstr, size_t rstr_len, const char *charset, size_t charset_len);

#endif // __SYSTEMRAND_H__
