#include "common/memzero.h"
#include "crypto/kex.h"
#include "crypto/kex_ecc.h"
#include "crypto/types.h"
#include "test.h"

void test_kex_ecc(const kex_curve_t curve, const char *authkey1,
                  size_t authkey1_len, const char *authkey2,
                  size_t authkey2_len, int expect_auth_pass) {
  kex_t kex_peer1;
  kex_t kex_peer2;

  kex_peer_share_t peer1_data;
  kex_peer_share_t peer2_data;
  kex_t *kex_peer1_ptr = &kex_peer1;
  kex_t *kex_peer2_ptr = &kex_peer2;

  unsigned char *shared_key1;
  unsigned char *shared_key2;
  size_t shared_key1_len;
  size_t shared_key2_len;

  /* Allocate kex interface */
  ASSERT(kex_intf_curve_is_supported(&kex_ecc_intf, curve) == 1);
  ASSERT(kex_intf_alloc(&kex_ecc_intf, &kex_peer1_ptr, curve) == ERR_SUCCESS);
  ASSERT(kex_intf_alloc(&kex_ecc_intf, &kex_peer2_ptr, curve) == ERR_SUCCESS);

  /* Generate key pair */
  ASSERT(kex_key_gen(kex_peer1_ptr) == ERR_SUCCESS);
  ASSERT(kex_key_gen(kex_peer2_ptr) == ERR_SUCCESS);

  /* Get peer data */
  ASSERT(kex_get_peer_data(kex_peer1_ptr, &peer1_data, authkey1,
                           authkey1_len) == ERR_SUCCESS);
  ASSERT(kex_get_peer_data(kex_peer2_ptr, &peer2_data, authkey2,
                           authkey2_len) == ERR_SUCCESS);

  if (expect_auth_pass) {
    /* Derive shared key (on both 'sides') */
    ASSERT(kex_derive_shared_key(kex_peer1_ptr, &peer2_data, authkey1,
                                 authkey1_len, &shared_key1,
                                 &shared_key1_len) == ERR_SUCCESS);
    ASSERT(kex_derive_shared_key(kex_peer2_ptr, &peer1_data, authkey2,
                                 authkey2_len, &shared_key2,
                                 &shared_key2_len) == ERR_SUCCESS);

    /* Check if shared keys are equal */
    ASSERT_EQ(shared_key1_len, shared_key2_len);
    ASSERT_MEMEQ(shared_key1, shared_key2, shared_key1_len);
  } else {
    ASSERT(kex_derive_shared_key(kex_peer1_ptr, &peer2_data, authkey1,
                                 authkey1_len, &shared_key1,
                                 &shared_key1_len) == ERR_AUTH_FAIL);
    ASSERT(kex_derive_shared_key(kex_peer2_ptr, &peer1_data, authkey2,
                                 authkey2_len, &shared_key2,
                                 &shared_key2_len) == ERR_AUTH_FAIL);
  }

  /* Cleanup */
  free(shared_key1);
  free(shared_key2);
  kex_free_peer_data(kex_peer1_ptr, &peer1_data);
  kex_free_peer_data(kex_peer2_ptr, &peer2_data);
  ASSERT(kex_dealloc(kex_peer1_ptr) == ERR_SUCCESS);
  ASSERT(kex_dealloc(kex_peer2_ptr) == ERR_SUCCESS);
}

int main() {
  const unsigned char *test_authkeys[] = {(unsigned char *)"the-auth-key", (unsigned char *)"must-be-equal"};

  /* Expect pass */
  test_kex_ecc(KEX_CURVE_secp256k1, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[0], strlen(test_authkeys[0]), 1);
  test_kex_ecc(KEX_CURVE_secp384r1, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[0], strlen(test_authkeys[0]), 1);
  test_kex_ecc(KEX_CURVE_secp521r1, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[0], strlen(test_authkeys[0]), 1);
  test_kex_ecc(KEX_CURVE_prime239v3, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[0], strlen(test_authkeys[0]), 1);
  test_kex_ecc(KEX_CURVE_prime256v1, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[0], strlen(test_authkeys[0]), 1);

  /* Expect fail */
  test_kex_ecc(KEX_CURVE_secp256k1, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[1], strlen(test_authkeys[1]), 0);
  test_kex_ecc(KEX_CURVE_secp384r1, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[1], strlen(test_authkeys[1]), 0);
  test_kex_ecc(KEX_CURVE_secp521r1, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[1], strlen(test_authkeys[1]), 0);
  test_kex_ecc(KEX_CURVE_prime239v3, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[1], strlen(test_authkeys[1]), 0);
  test_kex_ecc(KEX_CURVE_prime256v1, test_authkeys[0], strlen(test_authkeys[0]),
               test_authkeys[1], strlen(test_authkeys[1]), 0);

  exit(EXIT_SUCCESS);
}
