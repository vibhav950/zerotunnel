#include "crypto/kem.h"
#include "crypto/kem_kyber_defs.h"
#include "crypto/types.h"
#include "test.h"

#include <string.h>

int main() {
  kem_t kem;
  kem_t *pkem = &kem;

  uint8_t *pubkey, *ct, *ss_mine, *ss_theirs;
  size_t pubkey_len, ct_len, ss_mine_len, ss_theirs_len;

  kem_alg_t algs[] = {KEM_Kyber_512, KEM_Kyber_768, KEM_Kyber_1024};

  for (int i = 0; i < COUNTOF(algs); i++) {
    ASSERT(kem_intf_alloc(&kem_kyber_intf, &pkem, algs[i]) ==
           ERR_SUCCESS);
    ASSERT(kem_keygen(pkem, &pubkey, &pubkey_len) == ERR_SUCCESS);
    ASSERT(kem_encapsulate(pkem, pubkey, pubkey_len, &ct, &ct_len, &ss_mine,
                           &ss_mine_len) == ERR_SUCCESS);
    ASSERT(kem_decapsulate(pkem, ct, ct_len, &ss_theirs, &ss_theirs_len) ==
           ERR_SUCCESS);
    ASSERT_EQ(ss_mine_len, ss_theirs_len);
    ASSERT_MEMEQ(ss_mine, ss_theirs, ss_mine_len);
    printf("pubkey_len=%zu, ct_len=%zu, ss_mine_len=%zu, ss_theirs_len=%zu\n", pubkey_len, ct_len,
           ss_mine_len, ss_theirs_len);
    kem_mem_free(&kem_kyber_intf, pubkey, pubkey_len);
    kem_mem_free(&kem_kyber_intf, ct, ct_len);
    kem_mem_free(&kem_kyber_intf, ss_mine, ss_mine_len);
    kem_mem_free(&kem_kyber_intf, ss_theirs, ss_theirs_len);
    kem_dealloc(pkem);
  }

  return 0;
}
