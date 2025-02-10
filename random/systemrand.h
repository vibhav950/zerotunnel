#ifndef __SYSTEMRAND_H__
#define __SYSTEMRAND_H__

#include "rdrand.h"

#include <stddef.h>

int zt_systemrand_bytes(uint8_t *buf, size_t bytes);

int zt_systemrand_4bytes(uint32_t *buf, size_t bytes4);

int zt_systemrand_8bytes(uint64_t *buf, size_t bytes8);

/**
 * Place an 8-bit random value into \p rand.
 *
 * Returns 0 on success, -1 on failure.
 */
int zt_rand_u8(uint8_t *rand);

/**
 * Place a 16-bit random value into \p rand.
 *
 * Returns 0 on success, -1 on failure.
 */
int zt_rand_u16(uint16_t *rand);

/**
 * Place a 32-bit random value into \p rand.
 *
 * Returns 0 on success, -1 on failure.
 */
int zt_rand_u32(uint32_t *rand);

/**
 * Place an 64-bit random value into \p rand.
 *
 * Returns 0 on success, -1 on failure.
 */
int zt_rand_u64(uint64_t *rand);

int zt_rand_charset(char *rstr, size_t rstr_len, const char *charset,
                    size_t charset_len);

#endif // __SYSTEMRAND_H__
