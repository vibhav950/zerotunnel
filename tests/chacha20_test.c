/**
 * chacha20_test.c
 *
 * Test the ChaCha20 cipher. Test vectors taken from
 * https://datatracker.ietf.org/doc/html/draft-nir-cfrg-chacha20-poly1305
 */

// TODO: Add more test vectors

#include "crypto/cipher.h"
#include "crypto/cipher_defs.h"
#include "crypto/types.h"
#include "test.h"

int main() {
  cipher_t *p_chacha20 = NULL;
  size_t out_len;
  uint8_t key[CHACHA20_KEY_LEN], iv[CHACHA20_IV_LEN];
  uint8_t pt[64], ct[64], buf[64];

  read_hex("00000000000000000000000000000000"
           "00000000000000000000000000000000",
           key, 32);

  read_hex("00000000000000000000000000000000", iv, 16);

  read_hex("00000000000000000000000000000000"
           "00000000000000000000000000000000"
           "00000000000000000000000000000000"
           "00000000000000000000000000000000",
           pt, 64);

  read_hex("76b8e0ada0f13d90405d6ae55386bd28"
           "bdd219b8a08ded1aa836efcc8b770dc7"
           "da41597c5157488d7724e03fb8d84a37"
           "6a43b8f41518a11cc387b669b2ee6586",
           ct, 64);

  /**
   * Encrypt data
   */

  ASSERT(cipher_intf_alloc(&cipher_intf, &p_chacha20, CHACHA20_KEY_LEN,
                           CHACHA20_IV_LEN, CIPHER_CHACHA20) == ERR_SUCCESS);

  ASSERT(cipher_init(p_chacha20, key, CHACHA20_KEY_LEN,
                     CIPHER_OPERATION_ENCRYPT) == ERR_SUCCESS);

  ASSERT(cipher_set_iv(p_chacha20, iv, CHACHA20_IV_LEN) == ERR_SUCCESS);

  out_len = sizeof(ct);
  ASSERT(cipher_encrypt(p_chacha20, pt, sizeof(pt), buf, &out_len) ==
         ERR_SUCCESS);

  ASSERT_MEMEQ(buf, ct, sizeof(ct));

  cipher_dealloc(p_chacha20);

  /**
   * Decrypt data
   */

  ASSERT(cipher_intf_alloc(&cipher_intf, &p_chacha20, CHACHA20_KEY_LEN,
                           CHACHA20_IV_LEN, CIPHER_CHACHA20) == ERR_SUCCESS);

  ASSERT(cipher_init(p_chacha20, key, CHACHA20_KEY_LEN,
                     CIPHER_OPERATION_DECRYPT) == ERR_SUCCESS);

  ASSERT(cipher_set_iv(p_chacha20, iv, CHACHA20_IV_LEN) == ERR_SUCCESS);

  out_len = sizeof(buf);
  ASSERT(cipher_decrypt(p_chacha20, ct, sizeof(ct), buf, &out_len) ==
         ERR_SUCCESS);

  ASSERT_MEMEQ(buf, pt, sizeof(pt));

  cipher_dealloc(p_chacha20);

  return 0;
}
