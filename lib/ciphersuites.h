#ifndef __CIPHERSUITES_H__
#define __CIPHERSUITES_H__

#define CS_INTERNAL(_) (_cs_##_)

typedef struct _zt_cipher_suite_entry_st {
  const char *name; /* canonical ciphersuite name */
  const uint8_t id;
  const char *alias; /* short ciphersuite name */
  int cipher_algorithm;
  int aead_algorithm;
  int hmac_algorithm;
  int kex_curve;
  int kem_algorithm;
  int kdf_algorithm;
  int CS_INTERNAL(minver); /* minimum required version */
  int CS_INTERNAL(maxver); /* maximum required version */
} zt_cipher_suite_entry_st;

// clang-format off
/**
 * KAPPA ciphersuite identifier list. For a ciphersuite to be available at
 * runtime, the crypto engine must provide an implementation for its constituent
 * cryptographic primitives.
 *
 * Naming format: "KAPPA_{BLOCKCIPHER}_{HMAC}_{ECDH}_{KEM}_{KDF}"
 * - If BLOCKCIPHER="AES256" then cipher="AES-256-CTR", aead="AES-256-GCM"
 * - If BLOCKCIPHER="CHACHA20" then cipher="CHACHA20", aead="CHACHA20-POLY1305"
 *
 * Alias format: "K-{hex_val_uppercase}"
 * - For example, if Id=0xab then alias="K-AB"
 */

#define KAPPA_AES256_SHA3_256_X25519_KYBER512_ARGON2          0x01
#define KAPPA_AES256_SHA3_256_X25519_KYBER768_ARGON2          0x02
#define KAPPA_AES256_SHA3_512_X25519_KYBER1024_ARGON2         0x03
#define KAPPA_AES256_SHA3_256_X448_KYBER512_ARGON2            0x04
#define KAPPA_AES256_SHA3_256_X448_KYBER768_ARGON2            0x05
#define KAPPA_AES256_SHA3_512_X448_KYBER1024_ARGON2           0x06
#define KAPPA_CHACHA20_SHA3_256_X25519_KYBER512_ARGON2        0x07
#define KAPPA_CHACHA20_SHA3_256_X25519_KYBER768_ARGON2        0x08
#define KAPPA_CHACHA20_SHA3_512_X25519_KYBER1024_ARGON2       0x09
#define KAPPA_CHACHA20_SHA3_256_X448_KYBER512_ARGON2          0x0A
#define KAPPA_CHACHA20_SHA3_256_X448_KYBER768_ARGON2          0x0B
#define KAPPA_CHACHA20_SHA3_512_X448_KYBER1024_ARGON2         0x0C
#define KAPPA_AES256_SHA256_X25519_KYBER512_ARGON2            0x0D
#define KAPPA_AES256_SHA512_X25519_KYBER768_ARGON2            0x0E
#define KAPPA_AES256_SHA512_X25519_KYBER1024_ARGON2           0x0F
#define KAPPA_AES256_SHA256_X448_KYBER512_ARGON2              0x10
#define KAPPA_AES256_SHA512_X448_KYBER768_ARGON2              0x11
#define KAPPA_AES256_SHA512_X448_KYBER1024_ARGON2             0x12
#define KAPPA_CHACHA20_SHA256_X25519_KYBER512_ARGON2          0x13
#define KAPPA_CHACHA20_SHA512_X25519_KYBER768_ARGON2          0x14
#define KAPPA_CHACHA20_SHA512_X25519_KYBER1024_ARGON2         0x15
#define KAPPA_CHACHA20_SHA256_X448_KYBER512_ARGON2            0x16
#define KAPPA_CHACHA20_SHA512_X448_KYBER768_ARGON2            0x17
#define KAPPA_CHACHA20_SHA512_X448_KYBER1024_ARGON2           0x18

/**
 * zt_cipher_suite_info - get information about a cipher suite by Id
 * @param[in] csid cipher suite identifier
 * @return pointer to the name of the cipher suite, or NULL if not found
 */
const char *zt_cipher_suite_info(uint8_t csid,
                                 int *cipher,
                                 int *aead,
                                 int *hmac,
                                 int *kex,
                                 int *kem,
                                 int *kdf);

/**
 * zt_cipher_suite_info_from_alias - get cipher suite information from alias
 * @param[in] alias alias of the cipher suite
 * @return fixed-size cipher suite identifier, or 0 if not found
 */
uint8_t zt_cipher_suite_info_from_alias(const char *alias,
                                        int *cipher,
                                        int *aead,
                                        int *hmac,
                                        int *kex,
                                        int *kem,
                                        int *kdf);

/**
 * zt_cipher_suite_info_from_name - get cipher suite information from name
 * @param[in] name name of the cipher suite
 * @return fixed-size cipher suite identifier, or 0 if not found
 */
uint8_t zt_cipher_suite_info_from_name(const char *name,
                                       int *cipher,
                                       int *aead,
                                       int *hmac,
                                       int *kex,
                                       int *kem,
                                       int *kdf);

/**
 * zt_cipher_suite_info_from_repr - get cipher suite info from a valid string
 * representation
 * @param[in] repr name or alias of the cipher suite (delimited by '-' or '_')
 * @return fixed-size cipher suite identifier, or 0 if not found
 */
uint8_t zt_cipher_suite_info_from_repr(const char *repr,
                                       int *cipher,
                                       int *aead,
                                       int *hmac,
                                       int *kex,
                                       int *kem,
                                       int *kdf);

/**
 * zt_cipher_suite_name_from_alias - get name of a cipher suite from its alias
 * @param[in] alias alias of the cipher suite
 * @return pointer to the name of the cipher suite, or NULL if not found
 */
const char *zt_cipher_suite_name_from_alias(const char *alias);

#undef CS_INTERNAL

#endif /* __CIPHERSUITES_H__ */
