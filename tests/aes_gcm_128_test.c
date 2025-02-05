#include "aes_gcm_128_tvec.h"
#include "crypto/aead.h"
#include "crypto/cipher.h"
#include "crypto/types.h"
#include "test.h"

/* Use global stack memory here since tests are run sequentially */
static uint8_t buffer[64];

void test_aes_gcm_128_encr(const uint8_t *key, size_t key_len,
                           const uint8_t *iv, size_t iv_len, const uint8_t *pt,
                           size_t pt_len, const uint8_t *aad, size_t aad_len,
                           const uint8_t *expected_ct, const uint8_t *tag,
                           size_t tag_len) {
  size_t buffer_len = sizeof(buffer);
  cipher_t aes_gcm_128;
  cipher_t *p_aes_gcm_128 = &aes_gcm_128;

  ASSERT(cipher_intf_alloc(&aead_intf, &p_aes_gcm_128, key_len, tag_len,
                           AES_GCM_128) == ERR_SUCCESS);
  ASSERT(cipher_init(p_aes_gcm_128, key, key_len, CIPHER_OPERATION_ENCRYPT) ==
         ERR_SUCCESS);
  ASSERT(cipher_set_iv(p_aes_gcm_128, iv, iv_len) == ERR_SUCCESS);
  ASSERT(cipher_set_aad(p_aes_gcm_128, aad, aad_len) == ERR_SUCCESS);
  ASSERT(cipher_encrypt(p_aes_gcm_128, pt, pt_len, buffer, &buffer_len) ==
         ERR_SUCCESS);
  ASSERT_EQ(buffer_len, pt_len + tag_len);
  ASSERT_MEMEQ(buffer, expected_ct, pt_len);
  ASSERT_MEMEQ(buffer + pt_len, tag, tag_len);
  cipher_dealloc(p_aes_gcm_128);
}

void test_aes_gcm_128_decr(const uint8_t *key, size_t key_len,
                           const uint8_t *iv, size_t iv_len,
                           const uint8_t *data, size_t data_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *expected_pt,
                           const size_t expected_pt_len, const size_t tag_len,
                           const int expect_pass) {
  size_t buffer_len = sizeof(buffer);
  cipher_t aes_gcm_128;
  cipher_t *p_aes_gcm_128 = &aes_gcm_128;

  ASSERT(cipher_intf_alloc(&aead_intf, &p_aes_gcm_128, key_len, tag_len,
                           AES_GCM_128) == ERR_SUCCESS);
  ASSERT(cipher_init(p_aes_gcm_128, key, key_len, CIPHER_OPERATION_DECRYPT) ==
         ERR_SUCCESS);
  ASSERT(cipher_set_iv(p_aes_gcm_128, iv, iv_len) == ERR_SUCCESS);
  ASSERT(cipher_set_aad(p_aes_gcm_128, aad, aad_len) == ERR_SUCCESS);
  if (expect_pass) {
    ASSERT(cipher_decrypt(p_aes_gcm_128, data, data_len, buffer, &buffer_len) ==
           ERR_SUCCESS);
    ASSERT_EQ(buffer_len, expected_pt_len);
    ASSERT_MEMEQ(buffer, expected_pt, expected_pt_len);
  } else {
    ASSERT(cipher_decrypt(p_aes_gcm_128, data, data_len, buffer, &buffer_len) ==
           ERR_AUTH_FAIL);
  }
  cipher_dealloc(p_aes_gcm_128);
}

int main() {
  /* Encryption */
  /* Test case #0 */
  test_aes_gcm_128_encr(aes_gcm_128_key_0, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_0, AES_GCM_IV_LEN, aes_gcm_128_pt_0,
                        sizeof(aes_gcm_128_pt_0), aes_gcm_128_aad_0,
                        sizeof(aes_gcm_128_aad_0), aes_gcm_128_ct_0,
                        aes_gcm_128_tag_0, AES_GCM_AUTH_TAG_LEN_LONG);

  /* Test case #1 */
  test_aes_gcm_128_encr(aes_gcm_128_key_1, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_1, AES_GCM_IV_LEN, aes_gcm_128_pt_1,
                        sizeof(aes_gcm_128_pt_1), aes_gcm_128_aad_1,
                        sizeof(aes_gcm_128_aad_1), aes_gcm_128_ct_1,
                        aes_gcm_128_tag_1, AES_GCM_AUTH_TAG_LEN_LONG);
  /* Test case #2 */
  test_aes_gcm_128_encr(aes_gcm_128_key_2, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_2, AES_GCM_IV_LEN, aes_gcm_128_pt_2,
                        sizeof(aes_gcm_128_pt_2), aes_gcm_128_aad_2,
                        sizeof(aes_gcm_128_aad_2), aes_gcm_128_ct_2,
                        aes_gcm_128_tag_2, AES_GCM_AUTH_TAG_LEN_LONG);

  /* Test case #3 */
  test_aes_gcm_128_encr(aes_gcm_128_key_3, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_3, AES_GCM_IV_LEN, aes_gcm_128_pt_3,
                        sizeof(aes_gcm_128_pt_3), NULL,
                        sizeof(aes_gcm_128_aad_3), aes_gcm_128_ct_3,
                        aes_gcm_128_tag_3, AES_GCM_AUTH_TAG_LEN_LONG);

  /* Test case #4 */
  test_aes_gcm_128_encr(aes_gcm_128_key_4, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_4, AES_GCM_IV_LEN, aes_gcm_128_pt_4,
                        sizeof(aes_gcm_128_pt_4), aes_gcm_128_aad_4,
                        sizeof(aes_gcm_128_aad_4), aes_gcm_128_ct_4,
                        aes_gcm_128_tag_4, AES_GCM_AUTH_TAG_LEN_LONG);

  /* Test case #5 */
  test_aes_gcm_128_encr(aes_gcm_128_key_5, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_5, AES_GCM_IV_LEN, aes_gcm_128_pt_5,
                        sizeof(aes_gcm_128_pt_5), aes_gcm_128_aad_5,
                        sizeof(aes_gcm_128_aad_5), aes_gcm_128_ct_5,
                        aes_gcm_128_tag_5, AES_GCM_AUTH_TAG_LEN_LONG);

  /* Decryption */
  /* Test case #6 */
  test_aes_gcm_128_decr(aes_gcm_128_key_6, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_6, AES_GCM_IV_LEN, aes_gcm_128_data_6,
                        sizeof(aes_gcm_128_data_6), aes_gcm_128_aad_6,
                        sizeof(aes_gcm_128_aad_6), aes_gcm_128_pt_6,
                        sizeof(aes_gcm_128_pt_6), AES_GCM_AUTH_TAG_LEN_LONG, 1);

  /* Test case #7 (FAIL) */
  test_aes_gcm_128_decr(
      aes_gcm_128_key_7, AES_GCM_128_KEY_LEN, aes_gcm_128_iv_7, AES_GCM_IV_LEN,
      aes_gcm_128_data_7, sizeof(aes_gcm_128_data_7), aes_gcm_128_aad_7,
      sizeof(aes_gcm_128_aad_7), NULL, 0, AES_GCM_AUTH_TAG_LEN_LONG, 0);

  /* Test case #8 */
  test_aes_gcm_128_decr(aes_gcm_128_key_8, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_8, AES_GCM_IV_LEN, aes_gcm_128_data_8,
                        sizeof(aes_gcm_128_data_8), aes_gcm_128_aad_8,
                        sizeof(aes_gcm_128_aad_8), aes_gcm_128_pt_8,
                        sizeof(aes_gcm_128_pt_8), AES_GCM_AUTH_TAG_LEN_LONG, 1);

  /* Test case #9 (FAIL) */
  test_aes_gcm_128_decr(
      aes_gcm_128_key_9, AES_GCM_128_KEY_LEN, aes_gcm_128_iv_9, AES_GCM_IV_LEN,
      aes_gcm_128_data_9, sizeof(aes_gcm_128_data_9), aes_gcm_128_aad_9,
      sizeof(aes_gcm_128_aad_9), NULL, 0, AES_GCM_AUTH_TAG_LEN_LONG, 0);

  /* Test case #10 */
  test_aes_gcm_128_decr(
      aes_gcm_128_key_10, AES_GCM_128_KEY_LEN, aes_gcm_128_iv_10,
      AES_GCM_IV_LEN, aes_gcm_128_data_10, sizeof(aes_gcm_128_data_10),
      aes_gcm_128_aad_10, sizeof(aes_gcm_128_aad_10), aes_gcm_128_pt_10,
      sizeof(aes_gcm_128_pt_10), AES_GCM_AUTH_TAG_LEN_LONG, 1);

  /* Test case #11 (FAIL) */
  test_aes_gcm_128_decr(aes_gcm_128_key_11, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_11, AES_GCM_IV_LEN, aes_gcm_128_data_11,
                        sizeof(aes_gcm_128_data_11), aes_gcm_128_aad_11,
                        sizeof(aes_gcm_128_aad_11), NULL, 0,
                        AES_GCM_AUTH_TAG_LEN_LONG, 0);

  /* Test case #12 */
  test_aes_gcm_128_decr(
      aes_gcm_128_key_12, AES_GCM_128_KEY_LEN, aes_gcm_128_iv_12,
      AES_GCM_IV_LEN, aes_gcm_128_data_12, sizeof(aes_gcm_128_data_12),
      aes_gcm_128_aad_12, sizeof(aes_gcm_128_aad_12), aes_gcm_128_pt_12,
      sizeof(aes_gcm_128_pt_12), AES_GCM_AUTH_TAG_LEN_LONG, 1);

  /* Test case #13 (FAIL) */
  test_aes_gcm_128_decr(aes_gcm_128_key_13, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_13, AES_GCM_IV_LEN, aes_gcm_128_data_13,
                        sizeof(aes_gcm_128_data_13), aes_gcm_128_aad_13,
                        sizeof(aes_gcm_128_aad_13), NULL, 0,
                        AES_GCM_AUTH_TAG_LEN_LONG, 0);

  /* Test case #14 */
  test_aes_gcm_128_decr(
      aes_gcm_128_key_14, AES_GCM_128_KEY_LEN, aes_gcm_128_iv_14,
      AES_GCM_IV_LEN, aes_gcm_128_data_14, sizeof(aes_gcm_128_data_14),
      aes_gcm_128_aad_14, sizeof(aes_gcm_128_aad_14), aes_gcm_128_pt_14,
      sizeof(aes_gcm_128_pt_14), AES_GCM_AUTH_TAG_LEN_LONG, 1);

  /* Test case #15 (FAIL) */
  test_aes_gcm_128_decr(aes_gcm_128_key_15, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_15, AES_GCM_IV_LEN, aes_gcm_128_data_15,
                        sizeof(aes_gcm_128_data_15), aes_gcm_128_aad_15,
                        sizeof(aes_gcm_128_aad_15), NULL, 0,
                        AES_GCM_AUTH_TAG_LEN_LONG, 0);

  /* Test case #16 */
  test_aes_gcm_128_decr(
      aes_gcm_128_key_16, AES_GCM_128_KEY_LEN, aes_gcm_128_iv_16,
      AES_GCM_IV_LEN, aes_gcm_128_data_16, sizeof(aes_gcm_128_data_16),
      aes_gcm_128_aad_16, sizeof(aes_gcm_128_aad_16), aes_gcm_128_pt_16,
      sizeof(aes_gcm_128_pt_16), AES_GCM_AUTH_TAG_LEN_LONG, 1);

  /* Test case #17 (FAIL) */
  test_aes_gcm_128_decr(aes_gcm_128_key_17, AES_GCM_128_KEY_LEN,
                        aes_gcm_128_iv_17, AES_GCM_IV_LEN, aes_gcm_128_data_17,
                        sizeof(aes_gcm_128_data_17), aes_gcm_128_aad_17,
                        sizeof(aes_gcm_128_aad_17), NULL, 0,
                        AES_GCM_AUTH_TAG_LEN_LONG, 0);

  exit(EXIT_SUCCESS);
}
