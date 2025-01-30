#ifndef __KYBER_KEM_OQS_H__
#define __KYBER_KEM_OQS_H__

/**
 * ML-KEM/Kyber approved parameter sets (FIPS 203).
 *
 * These defines MUST NOT be changed.
 */

#define KEM_KYBER_512_PUBKEY_SIZE       800
#define KEM_KYBER_512_PRIVKEY_SIZE      1632
#define KEM_KYBER_512_CIPHERTEXT_SIZE   768
#define KEM_KYBER_512_SHAREDKEY_SIZE    32

#define KEM_KYBER_768_PUBKEY_SIZE       1184
#define KEM_KYBER_768_PRIVKEY_SIZE      2400
#define KEM_KYBER_768_CIPHERTEXT_SIZE   1088
#define KEM_KYBER_768_SHAREDKEY_SIZE    32

#define KEM_KYBER_1024_PUBKEY_SIZE      1568
#define KEM_KYBER_1024_PRIVKEY_SIZE     3168
#define KEM_KYBER_1024_CIPHERTEXT_SIZE  1568
#define KEM_KYBER_1024_SHAREDKEY_SIZE   32

#if 1 /* defined(LIBOQS) */
#include <oqs/oqs.h>

#if !defined(OQS_ENABLE_KEM_kyber_512) ||                                      \
    !defined(OQS_ENABLE_KEM_kyber_768) || !defined(OQS_ENABLE_KEM_kyber_1024)
#error                                                                         \
    "liboqs must be configured with OQS_ENABLE_KEM_kyber_512, OQS_ENABLE_KEM_kyber_768, and OQS_ENABLE_KEM_kyber_1024"
#endif

typedef struct kem_oqs_ctx_st {
  OQS_KEM *kem;
} kem_oqs_ctx;
#endif

#endif /* __KYBER_KEM_OQS_H__ */
