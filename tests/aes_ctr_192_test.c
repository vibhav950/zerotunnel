// Tests sourced from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

#include "crypto/cipher.h"
#include "crypto/cipher_defs.h"
#include "crypto/types.h"
#include "test.h"

int main() {
  cipher_t *p_aes_ctr = NULL;
  size_t out_len;

  uint8_t k[24], pt[64], ct[64], buf[64], ctr[16];

  read_hex("6bc1bee22e409f96e93d7e117393172a"  // Block #1
           "ae2d8a571e03ac9c9eb76fac45af8e51"  // Block #2
           "30c81c46a35ce411e5fbc1191a0a52ef"  // Block #3
           "f69f2445df4f9b17ad2b417be66c3710", // Block #4
           pt, 64);

  read_hex("1abc932417521ca24f2b0459fe7e6e0b"  // Block #1
           "090339ec0aa6faefd5ccc2c6f4ce8e94"  // Block #2
           "1e36b26bd1ebc670d1bd1d665620abf7"  // Block #3
           "4f78a7f6d29809585a97daec58c6b050", // Block #4
           ct, 64);

  read_hex("8e73b0f7da0e6452c810f32b809079e56"
           "2f8ead2522c6b7b",
           k, 24);

  read_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", ctr, 16);

  /* F.5.3 CTR-AES192.Encrypt */
  ASSERT(cipher_intf_alloc(&cipher_intf, &p_aes_ctr, AES_CTR_192_KEY_LEN, 0,
                           CIPHER_AES_CTR_192) == ERR_SUCCESS);
  ASSERT(cipher_init(p_aes_ctr, k, AES_CTR_192_KEY_LEN,
                     CIPHER_OPERATION_ENCRYPT) == ERR_SUCCESS);
  ASSERT(cipher_set_iv(p_aes_ctr, ctr, AES_CTR_IV_LEN) == ERR_SUCCESS);
  out_len = sizeof(ct);
  ASSERT(cipher_encrypt(p_aes_ctr, pt, sizeof(pt), buf, &out_len) ==
         ERR_SUCCESS);
  ASSERT_MEMEQ(buf, ct, sizeof(ct));
  cipher_dealloc(p_aes_ctr);

  /* F.5.4 CTR-AES192.Decrypt */
  ASSERT(cipher_intf_alloc(&cipher_intf, &p_aes_ctr, AES_CTR_192_KEY_LEN, 0,
                           CIPHER_AES_CTR_192) == ERR_SUCCESS);
  ASSERT(cipher_init(p_aes_ctr, k, AES_CTR_192_KEY_LEN,
                     CIPHER_OPERATION_DECRYPT) == ERR_SUCCESS);
  ASSERT(cipher_set_iv(p_aes_ctr, ctr, AES_CTR_IV_LEN) == ERR_SUCCESS);
  out_len = sizeof(pt);
  ASSERT(cipher_decrypt(p_aes_ctr, ct, sizeof(ct), buf, &out_len) ==
         ERR_SUCCESS);
  ASSERT_MEMEQ(buf, pt, sizeof(pt));
  cipher_dealloc(p_aes_ctr);

  return 0;
}
