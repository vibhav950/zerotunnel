#ifndef __KDF_DEFS_H__
#define __KDF_DEFS_H__

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
 * Note: The implementation must use SHA-512 as the underlying digest
 * (this property is not configurable)
 */

#define KDF_PBKDF2_CFABLE_ITER 8192

#endif /* __KDF_DEFS_H__ */
