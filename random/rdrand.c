/**
 * rdrand.c
 */

#include "rdrand.h"

/**
 * Get 16-bit random number with RDRAND
 * and write the value to *therand.
 *
 * Returns 1 on success, 0 on underflow.
 */
extern inline int __attribute__((always_inline)) rdrand16_step(uint16_t *therand) {
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

extern inline int __attribute__((always_inline)) rdseed16_step(uint16_t *therand) {
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
extern inline int __attribute__((always_inline)) rdrand32_step(uint32_t *therand) {
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

extern inline int __attribute__((always_inline)) rdseed32_step(uint32_t *therand) {
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
extern inline int __attribute__((always_inline)) rdrand64_step(uint64_t *therand) {
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

extern inline int __attribute__((always_inline)) rdseed64_step(uint64_t *therand) {
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
