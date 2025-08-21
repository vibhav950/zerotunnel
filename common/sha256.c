/**
 * @file sha256.c
 * Functions for the SHA-256 digest.
 */

#include "sha256.h"
#include "defines.h"
#include "endianness.h"
#include "x86_cpuid.h"

#if defined(__GNUC__)
#include <stdint.h>
#include <x86intrin.h>
#elif defined(_MSC_VER)
#include <immintrin.h>
#else
#error "unsupported platform"
#endif

#include <string.h>

#define U32(x) x##UL

extern void sha256_process_alg(uint32_t state[8], const uint8_t data[], uint32_t length);

extern void sha256_process_x86(uint32_t state[8], const uint8_t data[], uint32_t length);

static inline void sha256_process(uint32_t state[8], const uint8_t data[],
                                  uint32_t length) {
#if defined(__SSE4_1__) && defined(__SHA__)
  if (HasSHA()) {
    sha256_process_x86(state, data, length);
#else
  if (0) {
#endif
  } else {
    sha256_process_alg(state, data, length);
  }
}

/** Initiate the SHA-256 state */
int sha256_init(sha256_ctx_t *ctx) {
  if (unlikely(!ctx))
    return -1;

  ctx->len = ctx->rem_len = 0;

  ctx->state[0] = U32(0x6a09e667);
  ctx->state[1] = U32(0xbb67ae85);
  ctx->state[2] = U32(0x3c6ef372);
  ctx->state[3] = U32(0xa54ff53a);
  ctx->state[4] = U32(0x510e527f);
  ctx->state[5] = U32(0x9b05688c);
  ctx->state[6] = U32(0x1f83d9ab);
  ctx->state[7] = U32(0x5be0cd19);
  return 0;
}

/** Update SHA-256 state with message blocks  */
int sha256_update(sha256_ctx_t *ctx, const uint8_t data[], size_t len) {
  if (unlikely(!ctx))
    return -1;

  // Accumulate overall input size
  ctx->len += len;

  // Buffer data that is less than a block
  if ((ctx->rem_len != 0) && (ctx->rem_len + len < SHA256_BLOCK_LEN)) {
    memcpy(&ctx->rem_data[ctx->rem_len], (void *)data, len);
    ctx->rem_len += len;
    return 0;
  }

  // Complete and process a previously stored block
  if (ctx->rem_len != 0) {
    const size_t clen = SHA256_BLOCK_LEN - ctx->rem_len;

    memcpy(&ctx->rem_data[ctx->rem_len], (void *)data, clen);
    sha256_process(ctx->state, ctx->rem_data, SHA256_BLOCK_LEN);

    data += clen;
    len -= clen;

    ctx->rem_len = 0;
    memzero(ctx->rem_data, SHA256_BLOCK_LEN);
  }

  // Compress whole blocks
  if (len >= SHA256_BLOCK_LEN) {
    // const size_t full_blocks_len = len & ~(SHA256_BLOCK_LEN - 1);
    const size_t full_blocks_len = (len / SHA256_BLOCK_LEN) * SHA256_BLOCK_LEN;

    sha256_process(ctx->state, data, full_blocks_len);

    data += full_blocks_len;
    len -= full_blocks_len;
  }

  // Store the remaining data
  memcpy(ctx->rem_data, (void *)data, len);
  ctx->rem_len = len;
  return 0;
}

/** Finalize the SHA-256 hash and reset the context */
int sha256_finalize(sha256_ctx_t *ctx, uint8_t hash[32]) {
  if (unlikely(!ctx || !hash))
    return -1;

  // Sanity check
  ASSERT(ctx->rem_len < SHA256_BLOCK_LEN);

  // Length of the original message in bits in big-endian format
#if defined(__LITTLE_ENDIAN__)
  uint64_t len_bits = bswap64(ctx->len << 3);
#else
  uint64_t len_bits = ctx->len << 3;
#endif

  // Append bit '1'
  ctx->rem_data[ctx->rem_len++] = 0x80;

  if (ctx->rem_len > SHA256_BLOCK_LEN - 8 /* 64 bits */) {
    zt_memset(&ctx->rem_data[ctx->rem_len], 0, SHA256_BLOCK_LEN - ctx->rem_len);

    sha256_process(ctx->state, ctx->rem_data, SHA256_BLOCK_LEN);

    zt_memset(ctx->rem_data, 0, SHA256_BLOCK_LEN);
  } else {
    zt_memset(&ctx->rem_data[ctx->rem_len], 0, SHA256_BLOCK_LEN - ctx->rem_len - 8);
  }

  // Append the length as a 64-bit BE integer
  memcpy(&ctx->rem_data[SHA256_BLOCK_LEN - 8], PTR8(&len_bits), 8);

  // Process the final block
  sha256_process(ctx->state, ctx->rem_data, SHA256_BLOCK_LEN);

  // Convert to big-endian ordering
#if defined(__LITTLE_ENDIAN__)
  ctx->state[0] = bswap32(ctx->state[0]);
  ctx->state[1] = bswap32(ctx->state[1]);
  ctx->state[2] = bswap32(ctx->state[2]);
  ctx->state[3] = bswap32(ctx->state[3]);
  ctx->state[4] = bswap32(ctx->state[4]);
  ctx->state[5] = bswap32(ctx->state[5]);
  ctx->state[6] = bswap32(ctx->state[6]);
  ctx->state[7] = bswap32(ctx->state[7]);
#endif

  memcpy(hash, ctx->state, SHA256_DIGEST_LEN);
  memzero(ctx, sizeof(sha256_ctx_t));
  return 0;
}

int SHA256(const uint8_t data[], size_t len, uint8_t hash[32]) {
  int ret = 0;
  sha256_ctx_t ctx;

  ret += sha256_init(&ctx);
  ret += sha256_update(&ctx, data, len);
  ret += sha256_finalize(&ctx, hash);
  return ret == 0 ? 0 : -1;
}

#if defined(DEBUG)
/**
 * Self-test routine against SHA-256 KATs; sourced from:
 * https://github.com/B-Con/crypto-algorithms/blob/master/sha256_test.c
 */
int sha256_self_test(void) {
  uint8_t text1[] = {"abc"};
  uint8_t text2[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
  uint8_t text3[] = {"aaaaaaaaaa"};
  uint8_t hash1[SHA256_DIGEST_LEN] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                      0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                      0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                      0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  uint8_t hash2[SHA256_DIGEST_LEN] = {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
                                      0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                                      0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
                                      0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};
  uint8_t hash3[SHA256_DIGEST_LEN] = {0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
                                      0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
                                      0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
                                      0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0};
  uint8_t buf[SHA256_DIGEST_LEN];
  sha256_ctx_t ctx;
  int idx;
  int pass = 1;

  ASSERT(sha256_init(&ctx) == 0);
  ASSERT(sha256_update(&ctx, text1, strlen(text1)) == 0);
  ASSERT(sha256_finalize(&ctx, buf) == 0);
  pass = pass && !memcmp(hash1, buf, SHA256_DIGEST_LEN);

  ASSERT(sha256_init(&ctx) == 0);
  ASSERT(sha256_update(&ctx, text2, strlen(text2)) == 0);
  ASSERT(sha256_finalize(&ctx, buf) == 0);
  pass = pass && !memcmp(hash2, buf, SHA256_DIGEST_LEN);

  ASSERT(sha256_init(&ctx) == 0);
  for (idx = 0; idx < 100000; ++idx)
    ASSERT(sha256_update(&ctx, text3, strlen(text3)) == 0);
  ASSERT(sha256_finalize(&ctx, buf) == 0);
  pass = pass && !memcmp(hash3, buf, SHA256_DIGEST_LEN);

  return pass;
}
#endif
