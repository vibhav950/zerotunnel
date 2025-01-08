#include "crypto/hmac.h"
#include "crypto/hmac_defs.h"
#include "crypto/types.h"
#include "hmac_tvec.h"
#include "test.h"

static uint8_t buffer[64];

void test_hmac(hmac_alg_t alg, const uint8_t *hmac_key, const size_t key_len,
               const uint8_t *hmac_data, const size_t hmac_data_len,
               const uint8_t *hmac_expected, const size_t hmac_expected_len) {
  hmac_t hmac;
  hmac_t *p_hmac = &hmac;

  ASSERT(hmac_intf_alloc(&hmac_intf, &p_hmac, key_len, key_len, alg) ==
         ERR_SUCCESS);
  ASSERT(hmac_init(p_hmac, hmac_key, key_len) == ERR_SUCCESS);
  ASSERT(hmac_update(p_hmac, hmac_data, hmac_data_len) == ERR_SUCCESS);
  ASSERT(hmac_compute(p_hmac, NULL, 0, buffer, hmac_expected_len) ==
         ERR_SUCCESS);
  ASSERT_MEMEQ(buffer, hmac_expected, hmac_expected_len);
  ASSERT(hmac_dealloc(p_hmac) == ERR_SUCCESS);
}

int main() {
  // Test HMAC-SHA-256
  test_hmac(HMAC_SHA256, key_256, HMAC_SHA256_KEY_LEN, data_256,
            HMAC_256_TVEC_DATA_1_LEN, sha256_hmacs[0], HMAC_SHA256_MAX_OUT_LEN);
  test_hmac(HMAC_SHA256, key_256, HMAC_SHA256_KEY_LEN, data_256,
            HMAC_256_TVEC_DATA_2_LEN, sha256_hmacs[1], HMAC_SHA256_MAX_OUT_LEN);
  test_hmac(HMAC_SHA256, key_256, HMAC_SHA256_KEY_LEN, data_256,
            HMAC_256_TVEC_DATA_3_LEN, sha256_hmacs[2], HMAC_SHA256_MAX_OUT_LEN);

  // Test HMAC-SHA-384
  test_hmac(HMAC_SHA384, key_384, HMAC_SHA384_KEY_LEN, data_384,
            HMAC_384_TVEC_DATA_1_LEN, sha384_hmacs[0], HMAC_SHA384_MAX_OUT_LEN);
  test_hmac(HMAC_SHA384, key_384, HMAC_SHA384_KEY_LEN, data_384,
            HMAC_384_TVEC_DATA_2_LEN, sha384_hmacs[1], HMAC_SHA384_MAX_OUT_LEN);
  test_hmac(HMAC_SHA384, key_384, HMAC_SHA384_KEY_LEN, data_384,
            HMAC_384_TVEC_DATA_3_LEN, sha384_hmacs[2], HMAC_SHA384_MAX_OUT_LEN);

  // Test HMAC-SHA-512
  test_hmac(HMAC_SHA512, key_512, HMAC_SHA512_KEY_LEN, data_512,
            HMAC_512_TVEC_DATA_1_LEN, sha512_hmacs[0], HMAC_SHA512_MAX_OUT_LEN);
  test_hmac(HMAC_SHA512, key_512, HMAC_SHA512_KEY_LEN, data_512,
            HMAC_512_TVEC_DATA_2_LEN, sha512_hmacs[1], HMAC_SHA512_MAX_OUT_LEN);
  test_hmac(HMAC_SHA512, key_512, HMAC_SHA512_KEY_LEN, data_512,
            HMAC_512_TVEC_DATA_3_LEN, sha512_hmacs[2], HMAC_SHA512_MAX_OUT_LEN);

  // Test HMAC-SHA3-256
  test_hmac(HMAC_SHA3_256, key_256, HMAC_SHA3_256_KEY_LEN, data_256,
            HMAC_256_TVEC_DATA_1_LEN, sha3_256_hmacs[0],
            HMAC_SHA3_256_MAX_OUT_LEN);
  test_hmac(HMAC_SHA3_256, key_256, HMAC_SHA3_256_KEY_LEN, data_256,
            HMAC_256_TVEC_DATA_2_LEN, sha3_256_hmacs[1],
            HMAC_SHA3_256_MAX_OUT_LEN);
  test_hmac(HMAC_SHA3_256, key_256, HMAC_SHA3_256_KEY_LEN, data_256,
            HMAC_256_TVEC_DATA_3_LEN, sha3_256_hmacs[2],
            HMAC_SHA3_256_MAX_OUT_LEN);

  // Test HMAC-SHA3-384
  test_hmac(HMAC_SHA3_384, key_384, HMAC_SHA3_384_KEY_LEN, data_384,
            HMAC_384_TVEC_DATA_1_LEN, sha3_384_hmacs[0],
            HMAC_SHA3_384_MAX_OUT_LEN);
  test_hmac(HMAC_SHA3_384, key_384, HMAC_SHA3_384_KEY_LEN, data_384,
            HMAC_384_TVEC_DATA_2_LEN, sha3_384_hmacs[1],
            HMAC_SHA3_384_MAX_OUT_LEN);
  test_hmac(HMAC_SHA3_384, key_384, HMAC_SHA3_384_KEY_LEN, data_384,
            HMAC_384_TVEC_DATA_3_LEN, sha3_384_hmacs[2],
            HMAC_SHA3_384_MAX_OUT_LEN);

  // Test HMAC-SHA3-512
  test_hmac(HMAC_SHA3_512, key_512, HMAC_SHA3_512_KEY_LEN, data_512,
            HMAC_512_TVEC_DATA_1_LEN, sha3_512_hmacs[0],
            HMAC_SHA3_512_MAX_OUT_LEN);
  test_hmac(HMAC_SHA3_512, key_512, HMAC_SHA3_512_KEY_LEN, data_512,
            HMAC_512_TVEC_DATA_2_LEN, sha3_512_hmacs[1],
            HMAC_SHA3_512_MAX_OUT_LEN);
  test_hmac(HMAC_SHA3_512, key_512, HMAC_SHA3_512_KEY_LEN, data_512,
            HMAC_512_TVEC_DATA_3_LEN, sha3_512_hmacs[2],
            HMAC_SHA3_512_MAX_OUT_LEN);

  exit(EXIT_SUCCESS);
}
