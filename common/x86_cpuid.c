
/**
 * x86_cpuid.c
 *
 * This file is part of the zerotunnel library.
 * Written and placed in the public domain by vibhav950.
 */

#include "x86_cpuid.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) ||              \
    defined(__i386)
#if defined(_MSC_VER)
// Visual Studio
#include <intrin.h> // __cpuid, __cpuidex
#elif defined(__GNUC__) || defined(__clang__)
// GCC / LLVM (Clang)
#include <cpuid.h> // __get_cpuid, __get_cpuid_count
#else
#error "unknown platform"
#endif
#else
#error "unknown architecture"
#endif

#include <stdint.h>

/** %ecx */
#define X86_BIT_SSE3    (1 << 0 )
#define X86_BIT_SSE4_1  (1 << 19)
#define X86_BIT_SSE4_2  (1 << 20)
#define X86_BIT_SSSE3   (1 << 9 )
#define X86_BIT_AVX     (1 << 28)
#define X86_BIT_AES     (1 << 25)
#define X86_BIT_RDRAND  (1 << 30)

/** %edx */
#define X86_BIT_SSE     (1 << 25)
#define X86_BIT_SSE2    (1 << 26)

/** %eax=7, %ecx=0 */
#define X86_BIT_AVX2    (1 << 5 )
#define X86_BIT_SHA     (1 << 29)
#define X86_BIT_RDSEED  (1 << 18)

volatile struct _x86_cpuid_features_st x86_cpuid_features = {0};

static inline void x86_cpuid(uint32_t l, uint32_t cpuid[4]) {
  cpuid[0] = 0;
  cpuid[1] = 0;
  cpuid[2] = 0;
  cpuid[3] = 0;
#if defined(_MSC_VER)
  __cpuid(cpuid, l);
#else
  __get_cpuid(l, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif
}

static inline void x86_cpuidex(uint32_t l, uint32_t sl, uint32_t cpuid[4]) {
  cpuid[0] = 0;
  cpuid[1] = 0;
  cpuid[2] = 0;
  cpuid[3] = 0;
#if defined(_MSC_VER)
  __cpuidex(cpuid, l, sl);
#else
  __get_cpuid_count(l, sl, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif
}

static inline int CheckIntel(uint32_t cpuid[4]) {
  // Check against the "GenuineIntel" string
  return (cpuid[1] /*ebx*/ == 0x756e6547) && (cpuid[2] /*ecx*/ == 0x6c65746e) &&
         (cpuid[3] /*edx*/ == 0x49656e69);
}

static inline int CheckAMD(uint32_t cpuid[4]) {
  // Check against the "AuthenticAMD" string
  return (cpuid[1] /*ebx*/ == 0x68747541) && (cpuid[2] /*ecx*/ == 0x444d4163) &&
         (cpuid[3] /*edx*/ == 0x69746e65);
}

void DetectX86CPUFeatures(void) {
  uint32_t cpuid[4];

  x86_cpuid(0, cpuid);
  x86_cpuid_features.fl_cpu_Intel = CheckIntel(cpuid);
  x86_cpuid_features.fl_cpu_AMD = CheckAMD(cpuid);

  x86_cpuid(1, cpuid);
  x86_cpuid_features.fl_SSE3 = (cpuid[2] & X86_BIT_SSE3) != 0;
  x86_cpuid_features.fl_SSE4_1 = (cpuid[2] & X86_BIT_SSE4_1) != 0;
  x86_cpuid_features.fl_SSE4_2 = (cpuid[2] & X86_BIT_SSE4_2) != 0;
  x86_cpuid_features.fl_SSSE3 = (cpuid[2] & X86_BIT_SSSE3) != 0;
  x86_cpuid_features.fl_AVX = (cpuid[2] & X86_BIT_AVX) != 0;
  x86_cpuid_features.fl_AES = (cpuid[2] & X86_BIT_AES) != 0;
  x86_cpuid_features.fl_RDRAND = (cpuid[2] & X86_BIT_RDRAND) != 0;
  x86_cpuid_features.fl_SSE = (cpuid[3] & X86_BIT_SSE) != 0;
  x86_cpuid_features.fl_SSE2 = (cpuid[3] & X86_BIT_SSE2) != 0;

  x86_cpuidex(7, 0, cpuid);
  x86_cpuid_features.fl_AVX2 = (cpuid[1] & X86_BIT_AVX2) != 0;
  x86_cpuid_features.fl_SHA = (cpuid[1] & X86_BIT_SHA) != 0;
  x86_cpuid_features.fl_RDSEED = (cpuid[1] & X86_BIT_RDSEED) != 0;
}

void DisableCPUExtendedFeatures(void) {
  x86_cpuid_features.fl_SSE3 = 0;
  x86_cpuid_features.fl_SSE4_1 = 0;
  x86_cpuid_features.fl_SSE4_2 = 0;
  x86_cpuid_features.fl_SSSE3 = 0;
  x86_cpuid_features.fl_AVX = 0;
  x86_cpuid_features.fl_AES = 0;
  x86_cpuid_features.fl_RDRAND = 0;
  x86_cpuid_features.fl_SSE = 0;
  x86_cpuid_features.fl_SSE2 = 0;
  x86_cpuid_features.fl_AVX2 = 0;
  x86_cpuid_features.fl_SHA = 0;
  x86_cpuid_features.fl_RDSEED = 0;
}
