#ifndef __VCRY_H__
#define __VCRY_H__

#include "crypto/cipher.h"
#include "crypto/hmac.h"
#include "crypto/kex.h"

/** AEAD ciphers */

#define VCRY_AEAD_AES_GCM_128         0x001
#define VCRY_AEAD_AES_GCM_192         0x002
#define VCRY_AEAD_AES_GCM_256         0x003
#define VCRY_AEAD_CHACHA20_POLY1305   0x004

#define VCRY_HMAC_SHA256              0x011
#define VCRY_HMAC_SHA384              0x012
#define VCRY_HMAC_SHA512              0x013
#define VCRY_HMAC_SHA3_256            0x014
#define VCRY_HMAC_SHA3_384            0x015
#define VCRY_HMAC_SHA3_512            0x016

/** Diffie-Hellman Ephemeral (Elliptic Curve) */

#define VCRY_KEX_ECDH_SECP256K1       0x021
#define VCRY_KEX_ECDH_SECP384R1       0x022
#define VCRY_KEX_ECDH_SECP521R1       0x023
#define VCRY_KEX_ECDH_PRIME239V3      0x024
#define VCRY_KEX_ECDH_PRIME256V1      0x025
#define VCRY_KEX_ECDH_X25519          0x026
#define VCRY_KEX_ECDH_X448            0x027

/** PQ-KEM */

#define VCRY_KEM_KYBER512             0x031
#define VCRY_KEM_KYBER768             0x032
#define VCRY_KEM_KYBER1024            0x033

/** Key Derivation Function */

#define VCRY_KDF_PBKDF2               0x041
#define VCRY_KDF_SCRYPT               0x042
#define VCRY_KDF_ARGON2               0x043

/**
 * Salt length
 * len(SALT) = len(SALT0) + len(SALT1) + len(SALT2)
*/
#define VCRY_HSHAKE_SALT_LEN           76UL
#define VCRY_HSHAKE_SALT0_LEN          32UL
#define VCRY_HSHAKE_SALT1_LEN          12UL
#define VCRY_HSHAKE_SALT2_LEN          32UL

/** Master key length */
#define VCRY_MASTER_KEY_LEN            32UL

/**
 * The session key consists of the MAC key (K_mac),
 * the encryption/decryption key (K_enc), and the
 * encryption/decryption IV (IV_enc) for the current
 * session.
 *
 * len(K_sess) = len(K_mac) + len(K_enc) + len(IV_enc)
 */
#define VCRY_SESSION_KEY_LEN           76UL
#define VCRY_MAC_KEY_LEN               32UL
#define VCRY_ENC_KEY_LEN               32UL
#define VCRY_ENC_IV_LEN                12UL

/**
 * Verification message length
 */
#define VCRY_VERIFY_MSG_LEN            32UL

/**
 * Constant strings for key derivation
 */
#define VCRY_HSHAKE_CONST0            "Derive the master key (K_pass)"
#define VCRY_HSHAKE_CONST1            "Derive the shared session key (K_sess)"

/**
 * Constant strings for session key verification
 */
#define VCRY_VERIFY_CONST0            "First proof message (Proof_A)"
#define VCRY_VERIFY_CONST1            "Second proof message (Proof_B)"

void vcry_set_role_initiator(void);
void vcry_set_role_responder(void);

int vcry_set_authkey(const uint8_t *authkey, size_t authkey_len);

void vcry_module_release(void);

int vcry_set_cipher_from_id(int id);
int vcry_set_hmac_from_id(int id);
int vcry_set_ecdh_from_id(int id);
int vcry_set_kem_from_id(int id);
int vcry_set_kdf_from_id(int id);

int vcry_set_cipher_from_name(const char *name);
int vcry_set_hmac_from_name(const char *name);
int vcry_set_ecdh_from_name(const char *name);
int vcry_set_kem_from_name(const char *name);
int vcry_set_kdf_from_name(const char *name);

int vcry_handshake_initiate(uint8_t **peerdata, size_t *peerdata_len);
int vcry_handshake_response(const uint8_t *peerdata_theirs, size_t peerdata_theirs_len, uint8_t **peerdata_mine, size_t *peerdata_mine_len);
int vcry_handshake_complete(const uint8_t *peerdata, size_t peerdata_len);

int vcry_derive_session_key(void);

int vcry_initiator_verify_initiate(uint8_t **verify_msg, size_t *verify_msg_len, const char *id_a, const char *id_b);
int vcry_responder_verify_initiate(uint8_t **verify_msg, size_t *verify_msg_len, const char *id_a, const char *id_b);

int vcry_initiator_verify_complete(const uint8_t verify_msg[VCRY_VERIFY_MSG_LEN], const char *id_a, const char *id_b);
int vcry_responder_verify_complete(const uint8_t verify_msg[VCRY_VERIFY_MSG_LEN], const char *id_a, const char *id_b);

int vcry_cipher_encrypt(uint8_t *pt, size_t pt_len, const uint8_t *ad, size_t ad_len, uint8_t *ct);
int vcry_cipher_decrypt(uint8_t *ct, size_t ct_len, const uint8_t *ad, size_t ad_len, uint8_t *pt);

#endif // __VCRY_H__
