#include "crypto/kex.h"
#include "crypto/kex_ecc.h"
#include "crypto/types.h"
#include "test.h"

void test_kex_ecc(const kex_curve_t curve) {
  kex_peer_share_t peer1_data;
  kex_peer_share_t peer2_data;
  kex_t *kex_peer1_ptr = NULL;
  kex_t *kex_peer2_ptr = NULL;

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
  ASSERT(kex_get_peer_data(kex_peer1_ptr, &peer1_data) == ERR_SUCCESS);
  ASSERT(kex_get_peer_data(kex_peer2_ptr, &peer2_data) == ERR_SUCCESS);

  /* Derive shared key (on both 'sides') */
  ASSERT(kex_derive_shared_key(kex_peer1_ptr, &peer2_data, &shared_key1,
                               &shared_key1_len) == ERR_SUCCESS);
  ASSERT(kex_derive_shared_key(kex_peer2_ptr, &peer1_data, &shared_key2,
                               &shared_key2_len) == ERR_SUCCESS);

  /* Cleanup */
  zt_free(shared_key1);
  zt_free(shared_key2);
  kex_free_peer_data(kex_peer1_ptr, &peer1_data);
  kex_free_peer_data(kex_peer2_ptr, &peer2_data);
  kex_dealloc(kex_peer1_ptr);
  kex_dealloc(kex_peer2_ptr);
}

int main() {
  test_kex_ecc(KEX_CURVE_prime239v3);
  test_kex_ecc(KEX_CURVE_prime256v1);
  test_kex_ecc(KEX_CURVE_secp256k1);
  test_kex_ecc(KEX_CURVE_secp384r1);
  test_kex_ecc(KEX_CURVE_secp521r1);
  test_kex_ecc(KEX_CURVE_X25519);
  test_kex_ecc(KEX_CURVE_X448);

  exit(EXIT_SUCCESS);
}
