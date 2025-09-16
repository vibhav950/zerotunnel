/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * cipher.h - AEAD and block ciphers
 */

#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "common/defines.h"

// clang-format off

typedef enum {
  CIPHER_FLAG_ALLOC = (1U << 0),
  CIPHER_FLAG_INIT  = (1U << 1),
  CIPHER_FLAG_AAD   = (1U << 2),
} cipher_flag_t;

/* List of potential cipher algorithms; the underlying
  crypto library must provide these options at runtime */
enum {
  CIPHER_AES_CTR_128     = (1U << 0),
  CIPHER_AES_CTR_192     = (1U << 1),
  CIPHER_AES_CTR_256     = (1U << 2),
  CIPHER_CHACHA20        = (1U << 3),
  AEAD_AES_GCM_128       = (1U << 4),
  AEAD_AES_GCM_192       = (1U << 5),
  AEAD_AES_GCM_256       = (1U << 6),
  AEAD_CHACHA20_POLY1305 = (1U << 7),
  AEAD_ALL               = AEAD_AES_GCM_128 |
                           AEAD_AES_GCM_192 |
                           AEAD_AES_GCM_256 |
                           AEAD_CHACHA20_POLY1305,
};

// clang-format on

/** Fixed-size cipher identifier */
typedef uint8_t cipher_alg_t;

typedef enum cipher_operation_st {
  CIPHER_OPERATION_DECRYPT = 1,
  CIPHER_OPERATION_ENCRYPT = 2,
} cipher_operation_t;

/** A pointer type for @p cipher_st, which is defined later */
typedef struct cipher_st *cipher_ptr_t;

typedef err_t (*cipher_alloc_func_t)(cipher_ptr_t *c, size_t key_len, size_t tag_len,
                                     cipher_alg_t alg);

typedef void (*cipher_dealloc_func_t)(cipher_ptr_t c);

typedef err_t (*cipher_init_func_t)(cipher_ptr_t c, const uint8_t *key, size_t key_len,
                                    cipher_operation_t oper);

typedef err_t (*cipher_set_iv_func_t)(cipher_ptr_t c, const uint8_t *iv, size_t iv_len);

typedef err_t (*cipher_set_aad_func_t)(cipher_ptr_t c, const uint8_t *aad,
                                       size_t aad_len);

typedef err_t (*cipher_encrypt_func_t)(cipher_ptr_t c, const uint8_t *in, size_t in_len,
                                       uint8_t *out, size_t *out_len);

typedef err_t (*cipher_decrypt_func_t)(cipher_ptr_t c, const uint8_t *in, size_t in_len,
                                       uint8_t *out, size_t *out_len);

typedef struct cipher_intf_st {
  cipher_alloc_func_t alloc;
  cipher_dealloc_func_t dealloc;
  cipher_init_func_t init;
  cipher_set_iv_func_t set_iv;
  cipher_set_aad_func_t set_aad;
  cipher_encrypt_func_t encrypt;
  cipher_decrypt_func_t decrypt;
  cipher_alg_t supported_algs;
} cipher_intf_t;

typedef struct cipher_st {
  const cipher_intf_t *intf;
  void *ctx;
  size_t key_len;
  size_t tag_len;
  cipher_operation_t oper;
  cipher_alg_t alg;
  cipher_flag_t flags;
} cipher_t;

/**
 * Convert a cipher algorithm enum to a human-readable string.
 *
 * @param[in] alg Cipher algorithm
 * @return String representation of the cipher algorithm
 */
const char *cipher_alg_to_string(cipher_alg_t alg);

/**
 * Check if a cipher algorithm is supported by the given cipher interface.
 *
 * @param[in] intf Cipher interface
 * @param[in] alg  Cipher algorithm to check
 * @return Non-zero if supported, zero otherwise
 */
int cipher_intf_alg_is_supported(const cipher_intf_t *intf, cipher_alg_t alg);

/**
 * Get the status of a specific flag in the cipher context.
 *
 * @param[in] c    Cipher context
 * @param[in] flag Cipher flag to check
 * @return Non-zero if the flag is set, zero otherwise
 */
int cipher_flag_get(cipher_t *c, cipher_flag_t flag);

/**
 * Get the tag length of the cipher context.
 *
 * @param[in] c Cipher context
 * @return Tag length in bytes
 */
size_t cipher_tag_len(cipher_t *c);

/**
 * Allocate a cipher context using the specified cipher interface.
 *
 * @param[in] intf    Cipher interface
 * @param[out] c      Pointer to the allocated cipher context
 * @param[in] key_len Length of the encryption/decryption key
 * @param[in] tag_len Length of the authentication tag (if applicable)
 * @param[in] alg     Cipher algorithm
 * @return ERR_SUCCESS on success, error code otherwise
 *
 * @note The allocated cipher context must be deallocated using `cipher_dealloc()`.
 */
err_t cipher_intf_alloc(const cipher_intf_t *intf, cipher_t **c, size_t key_len,
                        size_t tag_len, cipher_alg_t alg);

/**
 * Deallocate and securely erase a cipher context.
 *
 * @param[in] c Cipher context to deallocate
 * @return Void
 */
void cipher_dealloc(cipher_t *c);

/**
 * Initialize the cipher context with the provided key and operation mode.
 *
 * @param[in] c        Cipher context
 * @param[in] key      Key buffer
 * @param[in] key_len  Length of the key
 * @param[in] oper     Operation (encrypt or decrypt)
 * @return ERR_SUCCESS on success, error code otherwise
 */
err_t cipher_init(cipher_t *c, const uint8_t *key, size_t key_len,
                  cipher_operation_t oper);

/**
 * Set the initialization vector (IV) for the cipher context.
 *
 * @param[in] c      Cipher context
 * @param[in] iv     IV buffer
 * @param[in] iv_len Length of the IV
 * @return ERR_SUCCESS on success, error code otherwise
 */
err_t cipher_set_iv(cipher_t *c, const uint8_t *iv, size_t iv_len);

/**
 * Set the Additional Authenticated Data (AAD) for the cipher context.
 *
 * @param[in] c       Cipher context
 * @param[in] aad     AAD buffer
 * @param[in] aad_len Length of the AAD
 * @return ERR_SUCCESS on success, error code otherwise
 *
 * @warning This operation is not supported for non-AEAD ciphers.
 */
err_t cipher_set_aad(cipher_t *c, const uint8_t *aad, size_t aad_len);

/**
 * Encrypt data.
 *
 * @param[in]  c       Cipher context
 * @param[in]  in      Input buffer to encrypt
 * @param[in]  in_len  Length of input buffer
 * @param[out] out     Output buffer for encrypted data
 * @param[in,out] out_len On input: size of output buffer; on output: actual bytes written
 * @return ERR_SUCCESS on success, error code otherwise
 *
 * @note The output buffer must be at least `in_len + tag_len` bytes long for AEAD ciphers
 * and for non-AEAD ciphers, it must be at least `in_len` bytes long.
 */
err_t cipher_encrypt(cipher_t *c, const uint8_t *in, size_t in_len, uint8_t *out,
                     size_t *out_len);

/**
 * Decrypt data.
 *
 * @param[in]  c       Cipher context
 * @param[in]  in      Input buffer to decrypt
 * @param[in]  in_len  Length of input buffer
 * @param[out] out     Output buffer for decrypted data
 * @param[in,out] out_len On input: size of output buffer; on output: actual bytes written
 * @return ERR_SUCCESS on success, error code otherwise
 */
err_t cipher_decrypt(cipher_t *c, const uint8_t *in, size_t in_len, uint8_t *out,
                     size_t *out_len);

#endif /* __CIPHER_H__ */
