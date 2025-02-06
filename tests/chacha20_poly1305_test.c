#include "crypto/aead.h"
#include "crypto/cipher.h"
#include "crypto/types.h"
#include "test.h"

int main() {
  cipher_t chacha20_poly1305;
  cipher_t *p_chacha20_poly1305 = &chacha20_poly1305;
  size_t out_len;
  uint8_t key[CHACHA20_POLY1305_KEY_LEN], iv[CHACHA20_POLY1305_IV_LEN], aad[12];
  uint8_t pt[114], ct[114 + CHACHA20_POLY1305_AUTH_TAG_LEN_LONG];
  uint8_t buf[114 + CHACHA20_POLY1305_AUTH_TAG_LEN_LONG];

  read_hex("808182838485868788898a8b8c8d8e8f"
           "909192939495969798999a9b9c9d9e9f",
           key, 32);

  read_hex("808182838485868788898a8b", iv, 12);

  read_hex("50515253c0c1c2c3c4c5c6c7", aad, 12);

  read_hex("d31a8d34648e60db7b86afbc53ef7ec2"
           "a4aded51296e08fea9e2b5a736ee62d6"
           "3dbea45e8ca9671282fafb69da92728b"
           "1a71de0a9e060b2905d6a5b67ecd3b36"
           "92ddbd7f2d778b8c9803aee328091b58"
           "fab324e4fad675945585808b4831d7bc"
           "3ff4def08e4b7a9de576d26586cec64b"
           "6116",
           pt, 114);

  /**
   * Encrypt the data
   */

  ASSERT(cipher_intf_alloc(&aead_intf, &p_chacha20_poly1305,
                           CHACHA20_POLY1305_KEY_LEN,
                           CHACHA20_POLY1305_AUTH_TAG_LEN_LONG,
                           CIPHER_CHACHA20_POLY1305) == ERR_SUCCESS);

  ASSERT(cipher_init(p_chacha20_poly1305, key, CHACHA20_POLY1305_KEY_LEN,
                     CIPHER_OPERATION_ENCRYPT) == ERR_SUCCESS);

  ASSERT(cipher_set_iv(p_chacha20_poly1305, iv, CHACHA20_POLY1305_IV_LEN) ==
         ERR_SUCCESS);

  ASSERT(cipher_set_aad(p_chacha20_poly1305, aad, sizeof(aad)) == ERR_SUCCESS);

  out_len = sizeof(ct);
  ASSERT(cipher_encrypt(p_chacha20_poly1305, pt, sizeof(pt), ct, &out_len) ==
         ERR_SUCCESS);

  cipher_dealloc(p_chacha20_poly1305);

  /**
   * Decrypt the data we just encrypted
   */

  ASSERT(cipher_intf_alloc(&aead_intf, &p_chacha20_poly1305,
                           CHACHA20_POLY1305_KEY_LEN,
                           CHACHA20_POLY1305_AUTH_TAG_LEN_LONG,
                           CIPHER_CHACHA20_POLY1305) == ERR_SUCCESS);

  ASSERT(cipher_init(p_chacha20_poly1305, key, CHACHA20_POLY1305_KEY_LEN,
                     CIPHER_OPERATION_DECRYPT) == ERR_SUCCESS);

  ASSERT(cipher_set_iv(p_chacha20_poly1305, iv, CHACHA20_POLY1305_IV_LEN) ==
         ERR_SUCCESS);

  ASSERT(cipher_set_aad(p_chacha20_poly1305, aad, sizeof(aad)) == ERR_SUCCESS);

  out_len = sizeof(buf);
  ASSERT(cipher_decrypt(p_chacha20_poly1305, ct, sizeof(ct), buf, &out_len) ==
         ERR_SUCCESS);

  ASSERT_MEMEQ(pt, buf, 114);

  cipher_dealloc(p_chacha20_poly1305);

  return 0;
}
