/**
 * hex.c
 *
 * Original file: https://github.com/zbjornson/fast-hex
 *
 * =================================================================
 *
 * CHANGELOG:
 * [2-19-25] Modified by vibhav950 for zerotunnel
 */

#include "hex.h"
#include "common/defines.h"
#include "common/x86_cpuid.h"

#if defined(__GNUC__) // GCC, clang
#ifdef __clang__
#if __clang_major__ < 3 || (__clang_major__ == 3 && __clang_minor__ < 4)
#error("Requires clang >= 3.4")
#endif // clang >=3.4
#else
#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 8)
#error("Requires GCC >= 4.8")
#endif // gcc >=4.8
#endif // __clang__

#include <immintrin.h>
#elif defined(_MSC_VER)
#include <intrin.h>
#endif

#include <stddef.h>
#include <stdint.h>

// GCC and Clang support __restrict__ which can be used for C and C++
#if defined(_MSC_VER)
#define __restrict__ __restrict
#endif

// ASCII -> hex value
static const uint8_t unhex_table[256] = {
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
          0,         1,         2,         3,         4,         5,         6,         7,
          8,         9, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX,        10,        11,        12,        13,        14,        15, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX,        10,        11,        12,        13,        14,        15, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX
};

// ASCII -> hex value << 4 (upper nibble)
static const uint8_t unhex_table4[256] = {
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
          0,        16,        32,        48,        64,        80,        96,       112,
        128,       144, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX,       160,       176,       192,       208,       224,       240, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX,       160,       176,       192,       208,       224,       240, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX,
  UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX
};

// Looks up the value for the lower nibble.
static inline int8_t unhexB(uint8_t x) { return unhex_table[x]; }

// Looks up the value for the upper nibble. Equivalent to `unhexB(x) << 4`.
static inline int8_t unhexA(uint8_t x) { return unhex_table4[x]; }

#if defined(__AVX2__)
static inline int8_t unhexBitManip(uint8_t x) {
  return 9 * (x >> 6) + (x & 0xf);
}

inline static __m256i unhexBitManip256(const __m256i value) {
  __m256i _9 = _mm256_set1_epi16(9);
  __m256i _15 = _mm256_set1_epi16(0xf);

  __m256i and15 = _mm256_and_si256(value, _15);

#ifndef NO_MADDUBS
  __m256i sr6 = _mm256_srai_epi16(value, 6);
  __m256i mul = _mm256_maddubs_epi16(sr6, _9); // this has a latency of 5
#else
  // ... while this I think has a latency of 4, but worse throughput(?).
  // (x >> 6) * 9 is x * 8 + x:
  // ((x >> 6) << 3) + (x >> 6)
  // We need & 0b11 to emulate 8-bit operations (narrowest shift is 16b) -- or a left shift
  // (((x >> 6) & 0b11) << 3) + ((x >> 6) & 0b11)
  // or
  // tmp = (x >> 6) & 0b11
  // tmp << 3 + tmp
  // there's no carry due to the mask+shift combo, so + is |
  // tmp << 3 | tmp
  __m256i sr6_lo2 = _mm256_and_si256(_mm256_srli_epi16(value, 6), _mm256_set1_epi16(0b11));
  __m256i sr6_lo2_sl3 = _mm256_slli_epi16(sr6_lo2, 3);
  __m256i mul = _mm256_or_si256(sr6_lo2_sl3, sr6_lo2);
#endif

  __m256i add = _mm256_add_epi16(mul, and15);
  return add;
}

inline static __m256i hex256(__m256i value) {
  const __m256i HEX_LUTR = _mm256_setr_epi8(
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');
  return _mm256_shuffle_epi8(HEX_LUTR, value);
}

// (a << 4) | b;
// a and b must be 16-bit elements. Output is packed 8-bit elements.
inline static __m256i nib2byte(__m256i a1, __m256i b1, __m256i a2, __m256i b2) {
  __m256i a4_1 = _mm256_slli_epi16(a1, 4);
  __m256i a4_2 = _mm256_slli_epi16(a2, 4);
  __m256i a4orb_1 = _mm256_or_si256(a4_1, b1);
  __m256i a4orb_2 = _mm256_or_si256(a4_2, b2);
  __m256i pck1 = _mm256_packus_epi16(a4orb_1, a4orb_2); // lo1 lo2 hi1 hi2
  const int _0213 = 0b11011000;
  __m256i pck64 = _mm256_permute4x64_epi64(pck1, _0213);
  return pck64;
}


// a -> [a >> 4, a & 0b1111]
inline static __m256i byte2nib(__m128i val) {
  const __m256i ROT2 = _mm256_setr_epi8(
    -1, 0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14,
    -1, 0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14
  );
  __m256i doubled = _mm256_cvtepu8_epi16(val);
  __m256i hi = _mm256_srli_epi16(doubled, 4);
  __m256i lo = _mm256_shuffle_epi8(doubled, ROT2);
  __m256i bytes = _mm256_or_si256(hi, lo);
  bytes = _mm256_and_si256(bytes, _mm256_set1_epi8(0b1111));
  return bytes;
}

// len is number or dest bytes (i.e. half of src length)
static inline void decodeHexBMI(uint8_t* __restrict__ dest, const uint8_t* __restrict__ src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    uint8_t a = *src++;
    uint8_t b = *src++;
    a = unhexBitManip(a);
    b = unhexBitManip(b);
    dest[i] = (a << 4) | b;
  }
}

// len is number or dest bytes (i.e. half of src length)
static inline void decodeHexVec(uint8_t* __restrict__ dest, const uint8_t* __restrict__ src, size_t len) {
  const __m256i A_MASK = _mm256_setr_epi8(
    0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14, -1,
    0, -1, 2, -1, 4, -1, 6, -1, 8, -1, 10, -1, 12, -1, 14, -1);
  const __m256i B_MASK = _mm256_setr_epi8(
    1, -1, 3, -1, 5, -1, 7, -1, 9, -1, 11, -1, 13, -1, 15, -1,
    1, -1, 3, -1, 5, -1, 7, -1, 9, -1, 11, -1, 13, -1, 15, -1);

  const __m256i* val3 = (const __m256i *)src;
  __m256i* dec256 = (__m256i *)dest;

  while (len >= 32) {
    __m256i av1 = _mm256_lddqu_si256(val3++); // 32 nibbles, 16 bytes
    __m256i av2 = _mm256_lddqu_si256(val3++);
                                                // Separate high and low nibbles and extend into 16-bit elements
    __m256i a1 = _mm256_shuffle_epi8(av1, A_MASK);
    __m256i b1 = _mm256_shuffle_epi8(av1, B_MASK);
    __m256i a2 = _mm256_shuffle_epi8(av2, A_MASK);
    __m256i b2 = _mm256_shuffle_epi8(av2, B_MASK);

    // Convert ASCII values to nibbles
    a1 = unhexBitManip256(a1);
    a2 = unhexBitManip256(a2);
    b1 = unhexBitManip256(b1);
    b2 = unhexBitManip256(b2);

    // Nibbles to bytes
    __m256i bytes = nib2byte(a1, b1, a2, b2);

    _mm256_storeu_si256(dec256++, bytes);
    len -= 32;
  }

  src = (const uint8_t *)val3;
  dest = (uint8_t *)dec256;
  decodeHexBMI(dest, src, len);
}
#endif // defined(__AVX2__)

// // len is number of dest bytes
// static inline void decodeHexLUT(uint8_t* __restrict__ dest, const uint8_t* __restrict__ src, size_t len) {
//   for (size_t i = 0; i < len; i++) {
//     uint8_t a = *src++;
//     uint8_t b = *src++;
//     a = unhexB(a);
//     b = unhexB(b);
//     dest[i] = (a << 4) | b;
//   }
// }

// len is number of dest bytes
static inline void decodeHexLUT4(uint8_t* __restrict__ dest, const uint8_t* __restrict__ src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    uint8_t a = *src++;
    uint8_t b = *src++;
    a = unhexA(a);
    b = unhexB(b);
    dest[i] = a | b;
  }
}

static const char hex_table[16] = {
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};
inline static char hex(uint8_t value) { return hex_table[value]; }

// len is number of src bytes
static inline void encodeHex(uint8_t* __restrict__ dest, const uint8_t* __restrict__ src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    uint8_t a = src[i];
    uint8_t lo = a & 0b1111;
    uint8_t hi = a >> 4;
    *dest++ = hex(hi);
    *dest++ = hex(lo);
  }
}

#if defined(__AVX2__)
// len is number of src bytes
static inline void encodeHexVec(uint8_t* __restrict__ dest, const uint8_t* __restrict__ src, size_t len) {
  const __m128i* input128 = (const __m128i *)src;
  __m256i* output256 = (__m256i *)dest;

  size_t tailLen = len % 16;
  size_t vectLen = (len - tailLen) >> 4;
  for (size_t i = 0; i < vectLen; i++) {
    __m128i av = _mm_lddqu_si128(&input128[i]);
    __m256i nibs = byte2nib(av);
    __m256i hexed = hex256(nibs);
    _mm256_storeu_si256(&output256[i], hexed);
  }

  encodeHex(dest + (vectLen << 5), src + (vectLen << 4), tailLen);
}
#endif // defined(__AVX2__)

size_t zt_hex_decode(const uint8_t *src, size_t len, uint8_t **dst) {
  size_t buflen;

  ASSERT(src != NULL);
  ASSERT(dst != NULL);
  ASSERT(len % 2 == 0);

  buflen = len / 2;
  if (!(*dst = zt_malloc(buflen)))
    return 0;

#if defined(__AVX_2__)
  decodeHexVec(*dst, src, buflen);
#else
  decodeHexLUT4(*dst, src, buflen);
#endif

  return buflen;
}

size_t zt_hex_encode(const uint8_t *src, size_t len, uint8_t **dst) {
  size_t buflen;

  ASSERT(src != NULL);
  ASSERT(dst != NULL);

  buflen = (len * 2) + 1;
  if (!(*dst = zt_malloc(buflen)))
    return 0;
  (*dst)[buflen - 1] = '\0';

#if defined(__AVX2__)
  // do the runtime check for the AVX2 CPU feature flag (the program might intend to disable it)
  if (HasAVX2())
    encodeHexVec(*dst, src, len);
  else
    encodeHex(*dst, src, len);
#else
  encodeHex(*dst, src, len);
#endif

  return buflen - 1;
}
