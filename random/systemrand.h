#ifndef __SYSTEMRAND_H__
#define __SYSTEMRAND_H__

#include "rdrand.h"

#include <stddef.h>

int sys_rand_bytes(uint8_t *buf, size_t bytes);

int sys_rand_4bytes(uint32_t *buf, size_t bytes4);

int sys_rand_8bytes(uint64_t *buf, size_t bytes8);

/**
 * Place an 8-bit random value into \p rand.
 *
 * Returns 0 on success, -1 on failure.
 */
int rand_gen_u8(uint8_t *rand);

/**
 * Place a 16-bit random value into \p rand.
 *
 * Returns 0 on success, -1 on failure.
 */
int rand_gen_u16(uint16_t *rand);

/**
 * Place a 32-bit random value into \p rand.
 *
 * Returns 0 on success, -1 on failure.
 */
int rand_gen_u32(uint32_t *rand);

/**
 * Place an 64-bit random value into \p rand.
 *
 * Returns 0 on success, -1 on failure.
 */
int rand_gen_u64(uint64_t *rand);

int rand_gen_charset(char *rstr, size_t rstr_len, const char *charset,
                     size_t charset_len);

#endif // __SYSTEMRAND_H__
