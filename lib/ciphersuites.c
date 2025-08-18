#include "ciphersuites.h"
#include "protocol.h"
#include "vcry.h"

#define CS_ENTRY(csid, alias, cipher_alg, aead_alg, hmac_alg, kex_curve,       \
                 kem_alg, kdf_alg, minver, maxver)                             \
  [csid] = {#csid,     csid,    alias,   cipher_alg, aead_alg, hmac_alg,       \
            kex_curve, kem_alg, kdf_alg, minver,     maxver}

static const zt_cipher_suite_entry_st cs_entries[] = {
    {NULL, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0},
    CS_ENTRY(KAPPA_AES256_SHA3_256_X25519_KYBER512_ARGON2, "K-01",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA3_256,
             VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER512, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA3_256_X25519_KYBER768_ARGON2, "K-02",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA3_256,
             VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER768, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA3_512_X25519_KYBER1024_ARGON2, "K-03",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA3_512,
             VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER1024, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA3_256_X448_KYBER512_ARGON2, "K-04",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA3_256,
             VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER512, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA3_256_X448_KYBER768_ARGON2, "K-05",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA3_256,
             VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER768, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA3_512_X448_KYBER1024_ARGON2, "K-06",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA3_512,
             VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER1024, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA3_256_X25519_KYBER512_ARGON2, "K-07",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA3_256, VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER512,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA3_256_X25519_KYBER768_ARGON2, "K-08",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA3_256, VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER768,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA3_512_X25519_KYBER1024_ARGON2, "K-09",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA3_512, VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER1024,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA3_256_X448_KYBER512_ARGON2, "K-0A",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA3_256, VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER512,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA3_256_X448_KYBER768_ARGON2, "K-0B",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA3_256, VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER768,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA3_512_X448_KYBER1024_ARGON2, "K-0C",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA3_512, VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER1024,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA256_X25519_KYBER512_ARGON2, "K-0D",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA256,
             VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER512, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA512_X25519_KYBER768_ARGON2, "K-0E",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA512,
             VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER768, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA512_X25519_KYBER1024_ARGON2, "K-0F",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA512,
             VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER1024, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA256_X448_KYBER512_ARGON2, "K-10",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA256,
             VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER512, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA512_X448_KYBER768_ARGON2, "K-11",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA512,
             VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER768, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_AES256_SHA512_X448_KYBER1024_ARGON2, "K-12",
             VCRY_CIPHER_AES_CTR_256, VCRY_AEAD_AES_GCM_256, VCRY_HMAC_SHA512,
             VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER1024, VCRY_KDF_ARGON2,
             KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA256_X25519_KYBER512_ARGON2, "K-13",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA256, VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER512,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA512_X25519_KYBER768_ARGON2, "K-14",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA512, VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER768,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA512_X25519_KYBER1024_ARGON2, "K-15",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA512, VCRY_KEX_ECDH_X25519, VCRY_KEM_KYBER1024,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA256_X448_KYBER512_ARGON2, "K-16",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA256, VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER512,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA512_X448_KYBER768_ARGON2, "K-17",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA512, VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER768,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),

    CS_ENTRY(KAPPA_CHACHA20_SHA512_X448_KYBER1024_ARGON2, "K-18",
             VCRY_CIPHER_CHACHA20, VCRY_AEAD_CHACHA20_POLY1305,
             VCRY_HMAC_SHA512, VCRY_KEX_ECDH_X448, VCRY_KEM_KYBER1024,
             VCRY_KDF_ARGON2, KAPPAv1_unstable, KAPPA_UNKNOWN),
};

#define CS_ENTRIES_COUNT (sizeof(cs_entries) / sizeof(zt_cipher_suite_entry_st))

#define CS_VERSION_CHECK(entry)                                                \
  ((handshake_protocol_version_at_least(entry._cs_minver)) &&                  \
   (get_handshake_protocol_version() <= entry._cs_maxver))

#define CS_NAME_LOOP(name_str, stmts)                                          \
  for (idx = 1; idx < CS_ENTRIES_COUNT; idx++) {                               \
    if (strcasecmp(cs_entries[idx].name, name_str) == 0)                       \
      stmts                                                                    \
  }

#define CS_ALIAS_LOOP(alias_str, stmts)                                        \
  for (idx = 1; idx < CS_ENTRIES_COUNT; idx++) {                               \
    if (strcasecmp(cs_entries[idx].alias, alias_str) == 0)                     \
      stmts                                                                    \
  }

// clang-format off

const char *zt_cipher_suite_info(ciphersuite_t csid,
                                 int *cipher_algorithm,
                                 int *aead_algorithm,
                                 int *hmac_algorithm,
                                 int *kex_curve,
                                 int *kem_algorithm,
                                 int *kdf_algorithm) {
  if (csid == 0 || csid >= CS_ENTRIES_COUNT)
    return NULL;

  if (!CS_VERSION_CHECK(cs_entries[csid]))
    return NULL;

  if (cipher_algorithm)
    *cipher_algorithm = cs_entries[csid].cipher_algorithm;
  if (aead_algorithm)
    *aead_algorithm = cs_entries[csid].aead_algorithm;
  if (hmac_algorithm)
    *hmac_algorithm = cs_entries[csid].hmac_algorithm;
  if (kex_curve)
    *kex_curve = cs_entries[csid].kex_curve;
  if (kem_algorithm)
    *kem_algorithm = cs_entries[csid].kem_algorithm;
  if (kdf_algorithm)
    *kdf_algorithm = cs_entries[csid].kdf_algorithm;
  return cs_entries[csid].name;
}

ciphersuite_t zt_cipher_suite_info_from_alias(const char *alias,
                                              int *cipher_algorithm,
                                              int *aead_algorithm,
                                              int *hmac_algorithm,
                                              int *kex_curve,
                                              int *kem_algorithm,
                                              int *kdf_algorithm) {
  size_t idx;

  if (!alias || alias[0] == '\0')
    return 0;

  CS_ALIAS_LOOP(alias, { break; });

  if (idx == CS_ENTRIES_COUNT || !CS_VERSION_CHECK(cs_entries[idx]))
    return 0;

  if (cipher_algorithm)
    *cipher_algorithm = cs_entries[idx].cipher_algorithm;
  if (aead_algorithm)
    *aead_algorithm = cs_entries[idx].aead_algorithm;
  if (hmac_algorithm)
    *hmac_algorithm = cs_entries[idx].hmac_algorithm;
  if (kex_curve)
    *kex_curve = cs_entries[idx].kex_curve;
  if (kem_algorithm)
    *kem_algorithm = cs_entries[idx].kem_algorithm;
  if (kdf_algorithm)
    *kdf_algorithm = cs_entries[idx].kdf_algorithm;
  return cs_entries[idx].id;
}

ciphersuite_t zt_cipher_suite_info_from_name(const char *name,
                                             int *cipher_algorithm,
                                             int *aead_algorithm,
                                             int *hmac_algorithm,
                                             int *kex_curve,
                                             int *kem_algorithm,
                                             int *kdf_algorithm) {
  size_t idx;

  if (!name || name[0] == '\0')
    return 0;

  CS_NAME_LOOP(name, { break; });

  if (idx == CS_ENTRIES_COUNT || !CS_VERSION_CHECK(cs_entries[idx]))
    return 0;

  if (cipher_algorithm)
    *cipher_algorithm = cs_entries[idx].cipher_algorithm;
  if (aead_algorithm)
    *aead_algorithm = cs_entries[idx].aead_algorithm;
  if (hmac_algorithm)
    *hmac_algorithm = cs_entries[idx].hmac_algorithm;
  if (kex_curve)
    *kex_curve = cs_entries[idx].kex_curve;
  if (kem_algorithm)
    *kem_algorithm = cs_entries[idx].kem_algorithm;
  if (kdf_algorithm)
    *kdf_algorithm = cs_entries[idx].kdf_algorithm;
  return cs_entries[idx].id;
}

static inline void make_valid(const char *repr, char buf[64]) {
  size_t i;
  for (i = 0; i < MIN(strlen(repr), 63); i++)
    buf[i] = (repr[i] == '-') ? '_' : repr[i];
  buf[i] = '\0';
}

ciphersuite_t zt_cipher_suite_info_from_repr(const char *repr,
                                             int *cipher_algorithm,
                                             int *aead_algorithm,
                                             int *hmac_algorithm,
                                             int *kex_curve,
                                             int *kem_algorithm,
                                             int *kdf_algorithm) {
  size_t idx;
  char buf[64];

  if (!repr || repr[0] == '\0')
    return 0;

  if (strlen(repr) == sizeof("K-XX") - 1) {
    CS_ALIAS_LOOP(repr, { break; });
  } else {
    make_valid(repr, buf);
    CS_NAME_LOOP(buf, { break; });
  }

  if (idx == CS_ENTRIES_COUNT || !CS_VERSION_CHECK(cs_entries[idx]))
    return 0;

  if (cipher_algorithm)
    *cipher_algorithm = cs_entries[idx].cipher_algorithm;
  if (aead_algorithm)
    *aead_algorithm = cs_entries[idx].aead_algorithm;
  if (hmac_algorithm)
    *hmac_algorithm = cs_entries[idx].hmac_algorithm;
  if (kex_curve)
    *kex_curve = cs_entries[idx].kex_curve;
  if (kem_algorithm)
    *kem_algorithm = cs_entries[idx].kem_algorithm;
  if (kdf_algorithm)
    *kdf_algorithm = cs_entries[idx].kdf_algorithm;
  return cs_entries[idx].id;
}

const char *zt_cipher_suite_name_from_alias(const char *alias) {
  size_t idx;

  if (!alias || alias[0] == '\0')
    return NULL;

  CS_ALIAS_LOOP(alias, { break; });

  if (idx == CS_ENTRIES_COUNT || !CS_VERSION_CHECK(cs_entries[idx]))
    return NULL;
  return cs_entries[idx].name;
}
