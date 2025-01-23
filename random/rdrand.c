/**
 * rdrand.c
 */

#include "rdrand.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) ||              \
    defined(__i386)
#if defined(_MSC_VER)
// Visual Studio
#include <intrin.h> // __cpuid, __cpuidex
#elif defined(__GNUC__)
// GCC / LLVM (Clang)
#include <cpuid.h> // __get_cpuid, __get_cpuid_count
#endif
#endif

static inline int check_is_intel(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) ||              \
    defined(__i386)
#if defined(_MSC_VER) // Visual Studio
  int cpuid[4] = {-1};
  __cpuid(cpuid, 0);
#else // GCC / LLVM (Clang)
  unsigned int cpuid[4] = {0};
  __get_cpuid(0, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif

  // Check against the "GenuineIntel" string
  if ((cpuid[1] /*ebx*/ == 0x756e6547) && (cpuid[2] /*ecx*/ == 0x6c65746e) &&
      (cpuid[3] /*edx*/ == 0x49656e69)) {
    return 1;
  }
  return 0;
#else // unknown compiler architecture
  return 0;
#endif
}

static inline int check_is_amd(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) ||              \
    defined(__i386)
#if defined(_MSC_VER) // Visual Studio
  int cpuid[4] = {-1};
  __cpuid(cpuid, 0);
#else // GCC / LLVM (Clang)
  unsigned int cpuid[4] = {0};
  __get_cpuid(0, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif

  // Check against the "AuthenticAMD" string
  if ((cpuid[1] /*ebx*/ == 0x68747541) && (cpuid[2] /*ecx*/ == 0x444d4163) &&
      (cpuid[3] /*edx*/ == 0x69746e65)) {
    return 1;
  }
  return 0;
#else // unknown compiler architecture
  return 0;
#endif
}

static inline int check_rdrand(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) ||              \
    defined(__i386)
#if defined(_MSC_VER) // Visual Studio
  int cpuid[4] = {-1};
  __cpuid(cpuid, 1);
#else // GCC / LLVM (Clang)
  unsigned int cpuid[4] = {0};
  __get_cpuid(1, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif

  if ((cpuid[2] & 0x40000000) == 0x40000000) // rdrand bit (1 << 30)
    return 1;
  return 0;
#else // unknown compiler architecture
  return 0;
#endif
}

static inline int check_rdseed(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(_M_IX86) ||              \
    defined(__i386)
#if defined(_MSC_VER) // Visual Studio
  int cpuid[4] = {-1};
  __cpuidex(cpuid, 7, 0);
#else // GCC / LLVM (Clang)
  unsigned int cpuid[4] = {0};
  __get_cpuid_count(7, 0, &cpuid[0], &cpuid[1], &cpuid[2], &cpuid[3]);
#endif

  if ((cpuid[1] & 0x00040000) == 0x00040000) // rdseed bit (1 << 18)
    return 1;
  return 0;
#else // unknown compiler architecture
  return 0;
#endif
}

/* Returns 1 if RDRAND is available, 0 otherwise */
static inline int rdrand_check_support(void) {
  if ((check_is_intel() == 1) || (check_is_amd() == 1)) {
    if (check_rdrand() == 1)
      return 1;
  }
  return 0;
}

/* Returns 1 if RDSEED is available, 0 otherwise */
static inline int rdseed_check_support(void) {
  if ((check_is_intel() == 1) || (check_is_amd() == 1)) {
    if (check_rdseed() == 1)
      return 1;
  }
  return 0;
}

/**
 * Get 16-bit random number with RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
int rdrand16_step(uint16_t *therand) {
  uint16_t val;
  int cf_error_status;
  asm volatile("\n\
        rdrand %%ax;\n\
        mov $1,%%edx;\n\
        cmovae %%ax,%%dx;\n\
        mov %%edx,%1;\n\
        mov %%ax, %0;"
               : "=r"(val), "=r"(cf_error_status)::"%ax", "%dx");
  *therand = val;
  return cf_error_status;
}

int rdseed16_step(uint16_t *therand) {
  uint16_t val;
  int cf_error_status;
  asm volatile("\n\
        rdseed %%ax;\n\
        mov $1,%%edx;\n\
        cmovae %%ax,%%dx;\n\
        mov %%edx,%1;\n\
        mov %%ax, %0;"
               : "=r"(val), "=r"(cf_error_status)::"%ax", "%dx");
  *therand = val;
  return cf_error_status;
}

/**
 * Get 32-bit random number with RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
int rdrand32_step(uint32_t *therand) {
  uint32_t val;
  int cf_error_status;
  asm volatile("\n\
        rdrand %%eax;\n\
        mov $1,%%edx;\n\
        cmovae %%eax,%%edx;\n\
        mov %%edx,%1;\n\
        mov %%eax,%0;"
               : "=r"(val), "=r"(cf_error_status)::"%eax", "%edx");
  *therand = val;
  return cf_error_status;
}

int rdseed32_step(uint32_t *therand) {
  uint32_t val;
  int cf_error_status;
  asm volatile("\n\
        rdseed %%eax;\n\
        mov $1,%%edx;\n\
        cmovae %%eax,%%edx;\n\
        mov %%edx,%1;\n\
        mov %%eax,%0;"
               : "=r"(val), "=r"(cf_error_status)::"%eax", "%edx");
  *therand = val;
  return cf_error_status;
}

/**
 * Get 64-bit random number using RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
int rdrand64_step(uint64_t *therand) {
  uint64_t val;
  int cf_error_status;
  asm volatile("\n\
        rdrand %%rax;\n\
        mov $1,%%edx;\n\
        cmovae %%rax,%%rdx;\n\
        mov %%edx,%1;\n\
        mov %%rax, %0;"
               : "=r"(val), "=r"(cf_error_status)::"%rax", "%rdx");
  *therand = val;
  return cf_error_status;
}

int rdseed64_step(uint64_t *therand) {
  uint64_t val;
  int cf_error_status;
  asm volatile("\n\
        rdseed %%rax;\n\
        mov $1,%%edx;\n\
        cmovae %%rax,%%rdx;\n\
        mov %%edx,%1;\n\
        mov %%rax, %0;"
               : "=r"(val), "=r"(cf_error_status)::"%rax", "%rdx");
  *therand = val;
  return cf_error_status;
}

volatile int g_HasRDSEED = 0;
volatile int g_HasRDRAND = 0;

void DetectX86Rand() {
  if (check_is_intel() || check_is_amd()) {
    g_HasRDRAND = check_rdrand();
    g_HasRDSEED = check_rdseed();
  }
}
