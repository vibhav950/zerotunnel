#ifndef __VCRY_H__
#define __VCRY_H__

#include "common/defines.h"
#include "common/cbuf.h"
#include "crypto/cipher.h"
#include "crypto/hmac.h"
#include "crypto/kex.h"

/** Ciphers */

#define VCRY_CIPHER_AES_CTR_128       0x001
#define VCRY_CIPHER_AES_CTR_192       0x002
#define VCRY_CIPHER_AES_CTR_256       0x003
#define VCRY_CIPHER_CHACHA20          0x004

/** AEAD ciphers  */

#define VCRY_AEAD_AES_GCM_128         0x021
#define VCRY_AEAD_AES_GCM_192         0x022
#define VCRY_AEAD_AES_GCM_256         0x023
#define VCRY_AEAD_CHACHA20_POLY1305   0x024

#define VCRY_HMAC_SHA256              0x031
#define VCRY_HMAC_SHA384              0x032
#define VCRY_HMAC_SHA512              0x033
#define VCRY_HMAC_SHA3_256            0x034
#define VCRY_HMAC_SHA3_384            0x035
#define VCRY_HMAC_SHA3_512            0x036

/** Diffie-Hellman Ephemeral (Elliptic Curve) */

#define VCRY_KEX_ECDH_SECP256K1       0x041
#define VCRY_KEX_ECDH_SECP384R1       0x042
#define VCRY_KEX_ECDH_SECP521R1       0x043
#define VCRY_KEX_ECDH_PRIME239V3      0x044
#define VCRY_KEX_ECDH_PRIME256V1      0x045
#define VCRY_KEX_ECDH_X25519          0x046
#define VCRY_KEX_ECDH_X448            0x047

/** PQ-KEM */

#define VCRY_KEM_KYBER512             0x051
#define VCRY_KEM_KYBER768             0x052
#define VCRY_KEM_KYBER1024            0x053

/** Key Derivation Function */

#define VCRY_KDF_PBKDF2               0x061
#define VCRY_KDF_SCRYPT               0x062
#define VCRY_KDF_ARGON2               0x063

/**
 * Salt length
 * len(SALT) = len(SALT0) + len(SALT1) + len(SALT2)
 */
#define VCRY_HSHAKE_SALT_LEN           80UL
#define VCRY_HSHAKE_SALT0_LEN          32UL
#define VCRY_HSHAKE_SALT1_LEN          16UL
#define VCRY_HSHAKE_SALT2_LEN          32UL

/** Master key length */
#define VCRY_MASTER_KEY_LEN            32UL

/**
 * The session key consists of the MAC key (K_mac),
 * the encryption key (K_enc), and the encryption
 * initialization vector (IV_enc).
 *
 * K_sess = K_mac || K_enc || IV_enc
 *
 * len(K_sess) = len(K_mac) + len(K_enc) + len(IV_enc)
 */
#define VCRY_SESSION_KEY_LEN           76UL
#define VCRY_MAC_KEY_LEN               32UL
#define VCRY_ENC_KEY_LEN               32UL
#define VCRY_ENC_IV_LEN                12UL

#define VCRY_MAC_KEY_OFFSET            (0UL)
#define VCRY_ENC_KEY_OFFSET            (VCRY_MAC_KEY_LEN)
#define VCRY_ENC_IV_OFFSET             (VCRY_MAC_KEY_LEN + VCRY_ENC_KEY_LEN)

/**
 * Verification message length
 */
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

/** Get the most recent failure status code */
error_t vcry_get_last_err(void);

/** Clear the most recent failure status code */
void vcry_clear_last_err(void);

void vcry_set_role_initiator(void);
void vcry_set_role_responder(void);

error_t vcry_set_authpass(const uint8_t *authpass, size_t authkey_len);

void vcry_module_release(void);

error_t vcry_set_cipher_from_id(int id);
error_t vcry_set_aead_from_id(int id);
error_t vcry_set_hmac_from_id(int id);
error_t vcry_set_ecdh_from_id(int id);
error_t vcry_set_kem_from_id(int id);
error_t vcry_set_kdf_from_id(int id);

error_t vcry_set_cipher_from_name(const char *name);
error_t vcry_set_aead_from_name(const char *name);
error_t vcry_set_hmac_from_name(const char *name);
error_t vcry_set_ecdh_from_name(const char *name);
error_t vcry_set_kem_from_name(const char *name);
error_t vcry_set_kdf_from_name(const char *name);

error_t vcry_handshake_initiate(uint8_t **peerdata, size_t *peerdata_len);

error_t vcry_handshake_respond(const uint8_t *peerdata_theirs,
                               size_t peerdata_theirs_len,
                               uint8_t **peerdata_mine,
                               size_t *peerdata_mine_len);

error_t vcry_handshake_complete(const uint8_t *peerdata, size_t peerdata_len);

error_t vcry_derive_session_key(void);

error_t vcry_initiator_verify_initiate(uint8_t **verify_msg,
                                       size_t *verify_msg_len, const char *id_a,
                                       const char *id_b);
error_t vcry_responder_verify_initiate(uint8_t **verify_msg,
                                       size_t *verify_msg_len, const char *id_a,
                                       const char *id_b);

error_t
vcry_initiator_verify_complete(const uint8_t verify_msg[VCRY_VERIFY_MSG_LEN],
                               const char *id_a, const char *id_b);
error_t
vcry_responder_verify_complete(const uint8_t verify_msg[VCRY_VERIFY_MSG_LEN],
                               const char *id_a, const char *id_b);

error_t vcry_aead_encrypt(uint8_t *in, size_t in_len, const uint8_t *ad,
                          size_t ad_len, uint8_t *out, size_t *out_len);
error_t vcry_aead_decrypt(uint8_t *in, size_t in_len, const uint8_t *ad,
                          size_t ad_len, uint8_t *out, size_t *out_len);

#endif // __VCRY_H__
