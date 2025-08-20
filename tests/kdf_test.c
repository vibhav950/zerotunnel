#include "crypto/kdf.h"
#include "crypto/kdf_defs.h"
#include "crypto/types.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

static void test_kdf(kdf_alg_t alg) {
  kdf_t *p_kdf = NULL;
  uint8_t password[20];
  uint8_t salt[12];
  uint8_t buf1[32], buf2[32];
  uint8_t ad[20];

  ASSERT(kdf_intf_alloc(&kdf_intf, &p_kdf, alg) == ERR_SUCCESS);

  memset(password, 0x01, sizeof(password));
  memset(salt, 0x02, sizeof(salt));
  ASSERT(kdf_init(p_kdf, password, sizeof(password), salt, sizeof(salt)) ==
         ERR_SUCCESS);

  memset(ad, 0x0a, sizeof(ad));
  ASSERT(kdf_derive(p_kdf, ad, sizeof(ad), buf1, sizeof(buf1)) == ERR_SUCCESS);
  ASSERT(kdf_derive(p_kdf, ad, sizeof(ad), buf2, sizeof(buf2)) == ERR_SUCCESS);
  ASSERT_MEMEQ(buf1, buf2, sizeof(buf1));

  memset(ad, 0x0b, sizeof(ad));
  ASSERT(kdf_derive(p_kdf, ad, sizeof(ad), buf1, sizeof(buf2)) == ERR_SUCCESS);
  ASSERT_MEMNEQ(buf1, buf2, sizeof(buf1));

  memset(password, 0x0c, sizeof(password));
  ASSERT(kdf_init(p_kdf, password, sizeof(password), salt, sizeof(salt)) ==
         ERR_SUCCESS);

  ASSERT(kdf_derive(p_kdf, ad, sizeof(ad), buf2, sizeof(buf1)) == ERR_SUCCESS);
  ASSERT_MEMNEQ(buf1, buf2, sizeof(buf1));

  kdf_dealloc(p_kdf);
}

int main() {
  test_kdf(KDF_ALG_scrypt);
  fprintf(stdout, "Scrypt -- PASSED\n");

  test_kdf(KDF_ALG_PBKDF2);
  fprintf(stdout, "PBKDF2 -- PASSED\n");

  test_kdf(KDF_ALG_argon2);
  fprintf(stdout, "Argon2 -- PASSED\n");

  return 0;
}
