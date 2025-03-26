#ifndef __KDF_DEFS_H__
#define __KDF_DEFS_H__

#include "common/endianness.h"
#include "kdf.h"

/** Max password length in bytes */
#define KDF_MAX_PASSWORD_LEN 1024
/** Max salt length in bytes */
#define KDF_MAX_SALT_LEN 128
/** Maximum keystream length in bytes */
#define KDF_MAX_KEYSTREAM_LEN 1024
/** Maximum number of bytes between initializations */
#define KDF_MAX_REINIT_BYTES (1 << 12)

/**
 * Defines for Scrypt configurables
 *
 * Default values are set to:
 *  - N (KDF_SCRYPT_CFABLE_N) = 16384
 *  - r (KDF_SCRYPT_CFABLE_R) = 8
 *  - p (KDF_SCRYPT_CFABLE_P) = 2 (may downscale to 1)
 * Note: The memory requirement is 128 * N * r * p bytes. If you change these
 * values, you will also need to change the KDF_SCRYPT_CFABLE_MAXMEM define.
 */

#define KDF_SCRYPT_CFABLE_N 16384
#define KDF_SCRYPT_CFABLE_R 8
#define KDF_SCRYPT_CFABLE_P 2
#define KDF_SCRYPT_CFABLE_MAXMEM 33554432

/**
 * Defines for Argon2 configurables
 *
 * Default values are set to:
 *  - Iter (KDF_ARGON2_CFABLE_ITER) = 10
 *  - Memory (KDF_ARGON2_CFABLE_MEM) = 32 (32k bytes)
 *  - Threads (KDF_ARGON2_CFABLE_THREADS) = 4 (may downscale to 1)
 *  - Lanes (KDF_ARGON2_CFABLE_LANES) = 4 (equal to threads)
 */

#define KDF_ARGON2_CFABLE_ITER 10
#define KDF_ARGON2_CFABLE_MEM 32
#define KDF_ARGON2_CFABLE_THREADS 4
#define KDF_ARGON2_CFABLE_LANES (KDF_ARGON2_CFABLE_THREADS)

/**
 * Defines for PBKDF2 configurables
 *
 * Default values are set to:
 *  - Iter (KDF_PBKDF2_CFABLE_ITER) = 8192
 * Note: The implementation must use SHA-512 as the underlying digest (this
 * property is not configurable)
 */

#define KDF_PBKDF2_CFABLE_ITER 8192

/** Macros for 128-bit counter */

/** Set the counter using 4x 32-bit values */
#define KDF_CTR_SET(kdf, c0, c1, c2, c3)                                       \
  do {                                                                         \
    (kdf)->ctr.words[0] = c0;                                                  \
    (kdf)->ctr.words[1] = c1;                                                  \
    (kdf)->ctr.words[2] = c2;                                                  \
    (kdf)->ctr.words[3] = c3;                                                  \
  } while (0)

/** Get the counter as 4x 32-bit values */
#define KDF_CTR_GET(kdf, c0, c1, c2, c3)                                       \
  do {                                                                         \
    c0 = (kdf)->ctr.words[0];                                                  \
    c1 = (kdf)->ctr.words[1];                                                  \
    c2 = (kdf)->ctr.words[2];                                                  \
    c3 = (kdf)->ctr.words[3];                                                  \
  } while (0)

/**
 * Add a 32-bit value to the last 4 bytes of the counter, represented in
 * big-endian format
 */
#if defined(__LITTLE_ENDIAN__)
#define KDF_CTR_INCR32(kdf, inc)                                               \
  do {                                                                         \
    (kdf)->ctr.words[3] = BSWAP32(BSWAP32((kdf)->ctr.words[3]) + inc);         \
  } while (0)
#else
#define KDF_CTR_INCR32(kdf, inc)                                               \
  do {                                                                         \
    (kdf)->ctr.words[3] += inc;                                                \
  } while (0)
#endif

#if (1) // defined OPENSSL

#include <openssl/evp.h>

typedef struct kdf_ossl_ctx_st {
  EVP_KDF *kdf;
  EVP_KDF_CTX *kctx;
} kdf_ossl_ctx;

#endif /* OPENSSL */

#endif /* __KDF_DEFS_H__ */
