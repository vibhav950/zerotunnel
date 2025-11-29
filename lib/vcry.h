/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * vcry.h - Virtual cryptography interface
 */

#ifndef __VCRY_H__
#define __VCRY_H__

#include "common/defines.h"
#include "crypto/cipher.h"
#include "crypto/hmac.h"
#include "crypto/kex.h"

// clang-format off

/** Block ciphers */
#define VCRY_CIPHER_AES_CTR_128       0x001
#define VCRY_CIPHER_AES_CTR_192       0x002
#define VCRY_CIPHER_AES_CTR_256       0x003
#define VCRY_CIPHER_CHACHA20          0x004

/** AEAD ciphers */
#define VCRY_AEAD_AES_GCM_128         0x021
#define VCRY_AEAD_AES_GCM_192         0x022
#define VCRY_AEAD_AES_GCM_256         0x023
#define VCRY_AEAD_CHACHA20_POLY1305   0x024

/** Keyed MACs */
#define VCRY_HMAC_SHA256              0x031
#define VCRY_HMAC_SHA384              0x032
#define VCRY_HMAC_SHA512              0x033
#define VCRY_HMAC_SHA3_256            0x034
#define VCRY_HMAC_SHA3_384            0x035
#define VCRY_HMAC_SHA3_512            0x036

/** Diffie-Hellman ECC curves */
#define VCRY_KEX_ECDH_SECP256K1       0x041
#define VCRY_KEX_ECDH_SECP384R1       0x042
#define VCRY_KEX_ECDH_SECP521R1       0x043
#define VCRY_KEX_ECDH_PRIME239V3      0x044
#define VCRY_KEX_ECDH_PRIME256V1      0x045
#define VCRY_KEX_ECDH_X25519          0x046
#define VCRY_KEX_ECDH_X448            0x047

/** ML-KEM (Kyber) -- PQ-KEM */
#define VCRY_KEM_KYBER512             0x051
#define VCRY_KEM_KYBER768             0x052
#define VCRY_KEM_KYBER1024            0x053

/** Key derivation functions */
#define VCRY_KDF_PBKDF2               0x061
#define VCRY_KDF_SCRYPT               0x062
#define VCRY_KDF_ARGON2               0x063

/**
 * Initiator random salt (salt0 || salt1 || salt2)
 * len(salt) = len(salt0) + len(salt1) + len(salt2)
 */
#define VCRY_HSHAKE_SALT_LEN           80UL
#define VCRY_HSHAKE_SALT0_LEN          32UL
#define VCRY_HSHAKE_SALT1_LEN          16UL
#define VCRY_HSHAKE_SALT2_LEN          32UL

/** Master key length */
#define VCRY_MASTER_KEY_LEN            32UL


#define VCRY_K_MAC_LEN                 32UL
#define VCRY_K_ENCR_LEN                32UL
#define VCRY_IV_ENCR_LEN               12UL

/** K_sess = k0 || k1 || k2 || k3 || iv0 || iv1
 * where
 *  - k0 = K_mac_ini
 *  - k1 = K_mac_res
 *  - k2 = K_encr_ini
 *  - k3 = K_encr_res
 *  - iv0 = IV_encr_ini
 *  - iv1 = IV_encr_res
*/
#define VCRY_SESSION_KEY_LEN                                                   \
  ((VCRY_K_MAC_LEN + VCRY_K_ENCR_LEN + VCRY_IV_ENCR_LEN) * 2)

/** Verification message length */
#define VCRY_VERIFY_MSG_LEN            32UL

/**
 * Constant strings for key derivation
 */

#define VCRY_HSHAKE_CONST0            "Derive the master key (K_pass)"
#define VCRY_HSHAKE_CONST1            "Derive the session key (K_sess)"

/**
 * Constant strings for session key verification
 */

#define VCRY_VERIFY_CONST0            "First proof message (Proof_A)"
#define VCRY_VERIFY_CONST1            "Second proof message (Proof_B)"

#define VCRY_STREAM_ID_LEN            8UL
#define VCRY_STREAM_OFFSET_LEN        8UL

typedef struct _vcry_crypto_hdr_st {
  uint8_t sid[VCRY_STREAM_ID_LEN];      /* stream Id */
  uint8_t offs[VCRY_STREAM_OFFSET_LEN]; /* byte offset in stream */
} vcry_crypto_hdr_t;

// clang-format on

/** Get the most recent failure status code */
err_t vcry_get_last_err(void);

/** Clear the most recent failure status code */
void vcry_clear_last_err(void);

err_t vcry_module_init(void);

void vcry_set_role_initiator(void);
void vcry_set_role_responder(void);

err_t vcry_set_authpass(const uint8_t *authpass, size_t authkey_len);

void vcry_module_release(void);

err_t vcry_set_crypto_params(int cipher_id, int aead_id, int hmac_id, int kex_id,
                             int kem_id, int kdf_id);

err_t vcry_set_crypto_params_from_names(const char *cipher_name, const char *aead_name,
                                        const char *hmac_name, const char *kex_name,
                                        const char *kem_name, const char *kdf_name);

size_t vcry_get_aead_tag_len(void);
size_t vcry_get_hmac_digest_len(void);

err_t vcry_handshake_initiate(uint8_t **peerdata, size_t *peerdata_len);

err_t vcry_handshake_respond(const uint8_t *peerdata_theirs, size_t peerdata_theirs_len,
                             uint8_t **peerdata_mine, size_t *peerdata_mine_len);

err_t vcry_handshake_complete(const uint8_t *peerdata, size_t peerdata_len);

err_t vcry_derive_session_key(void);

err_t vcry_initiator_verify_initiate(uint8_t **verify_msg, size_t *verify_msg_len,
                                     const uint8_t *id_a, const uint8_t *id_b,
                                     size_t len_a, size_t len_b);
err_t vcry_responder_verify_initiate(uint8_t **verify_msg, size_t *verify_msg_len,
                                     const uint8_t *id_a, const uint8_t *id_b,
                                     size_t len_a, size_t len_b);

err_t vcry_initiator_verify_complete(const uint8_t verify_msg[VCRY_VERIFY_MSG_LEN],
                                     const uint8_t *id_a, const uint8_t *id_b,
                                     size_t len_a, size_t len_b);
err_t vcry_responder_verify_complete(const uint8_t verify_msg[VCRY_VERIFY_MSG_LEN],
                                     const uint8_t *id_a, const uint8_t *id_b,
                                     size_t len_a, size_t len_b);

vcry_crypto_hdr_t *vcry_crypto_hdr_new(uint8_t stream_id[VCRY_STREAM_ID_LEN]);

void vcry_crypto_hdr_free(vcry_crypto_hdr_t *hdr);

err_t vcry_aead_encrypt(uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len,
                        vcry_crypto_hdr_t *hdr, uint8_t *out, size_t *out_len);
err_t vcry_aead_decrypt(uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len,
                        vcry_crypto_hdr_t *hdr, uint8_t *out, size_t *out_len);

#endif // __VCRY_H__
