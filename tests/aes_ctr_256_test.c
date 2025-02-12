// Tests sourced from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

#include "crypto/cipher.h"
#include "crypto/cipher_defs.h"
#include "crypto/types.h"
#include "test.h"

int main() {
  cipher_t *p_aes_ctr = NULL;
  size_t out_len;

  uint8_t k[32], pt[64], ct[64], buf[64], ctr[16];

  read_hex("6bc1bee22e409f96e93d7e117393172a"  // Block #1
           "ae2d8a571e03ac9c9eb76fac45af8e51"  // Block #2
           "30c81c46a35ce411e5fbc1191a0a52ef"  // Block #3
           "f69f2445df4f9b17ad2b417be66c3710", // Block #4
           pt, 64);

  read_hex("601ec313775789a5b7a7f504bbf3d228"  // Block #1
           "f443e3ca4d62b59aca84e990cacaf5c5"  // Block #2
           "2b0930daa23de94ce87017ba2d84988d"  // Block #3
           "dfc9c58db67aada613c2dd08457941a6", // Block #4
           ct, 64);

  read_hex("603deb1015ca71be2b73aef0857d7781"
           "1f352c073b6108d72d9810a30914dff4",
           k, 32);

  read_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", ctr, 16);

  /* F.5.5 CTR-AES256.Encrypt */
  ASSERT(cipher_intf_alloc(&cipher_intf, &p_aes_ctr, AES_CTR_256_KEY_LEN, 0,
                           CIPHER_AES_CTR_256) == ERR_SUCCESS);
  ASSERT(cipher_init(p_aes_ctr, k, AES_CTR_256_KEY_LEN,
                     CIPHER_OPERATION_ENCRYPT) == ERR_SUCCESS);
  ASSERT(cipher_set_iv(p_aes_ctr, ctr, AES_CTR_IV_LEN) == ERR_SUCCESS);
  out_len = sizeof(ct);
  ASSERT(cipher_encrypt(p_aes_ctr, pt, sizeof(pt), buf, &out_len) ==
         ERR_SUCCESS);
  ASSERT_MEMEQ(buf, ct, sizeof(ct));
  cipher_dealloc(p_aes_ctr);

  /* F.5.6 CTR-AES256.Decrypt */
  ASSERT(cipher_intf_alloc(&cipher_intf, &p_aes_ctr, AES_CTR_256_KEY_LEN, 0,
                           CIPHER_AES_CTR_256) == ERR_SUCCESS);
  ASSERT(cipher_init(p_aes_ctr, k, AES_CTR_256_KEY_LEN,
                     CIPHER_OPERATION_DECRYPT) == ERR_SUCCESS);
  ASSERT(cipher_set_iv(p_aes_ctr, ctr, AES_CTR_IV_LEN) == ERR_SUCCESS);
  out_len = sizeof(pt);
  ASSERT(cipher_decrypt(p_aes_ctr, ct, sizeof(ct), buf, &out_len) ==
         ERR_SUCCESS);
  ASSERT_MEMEQ(buf, pt, sizeof(pt));
  cipher_dealloc(p_aes_ctr);

  return 0;
}
