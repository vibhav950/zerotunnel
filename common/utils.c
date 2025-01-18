#include "defs.h"

#include <assert.h>
#include <limits.h>

#define MASK_UCHAR     ((unsigned char)~0)
#define MASK_SCHAR     (MASK_UCHAR >> 1)

#define MASK_USHORT    ((unsigned short)~0)
#define MASK_SSHORT    (MASK_USHORT >> 1)

#define MASK_UINT      ((unsigned int)~0)
#define MASK_SINT      (MASK_UINT >> 1)

#define MASK_ULONG     ((unsigned long)~0)
#define MASK_SLONG     (MASK_ULONG >> 1)

#define MASK_ULONGLONG ((unsigned long long)~0)
#define MASK_SLONGLONG (MASK_ULONGLONG >> 1)

#define MASK_USIZE_T   ((size_t)~0)
#define MASK_SSIZE_T   (MASK_USIZE_T >> 1)

/** Unsigned long to unsigned short */
inline unsigned short ultous(unsigned long val) {
  assert(val <= (unsigned long)MASK_USHORT);
  return (unsigned short)(val & (unsigned long)MASK_USHORT);
}

/** Unsigned long to unsigned char  */
inline unsigned char ultouc(unsigned long val) {
  assert(val <= (unsigned long)MASK_UCHAR);
  return (unsigned char)(val & (unsigned long)MASK_UCHAR);
}

/** Unsigned long long to unsigned long */
inline unsigned long ulltoul(unsigned long long val) {
  assert(val <= (unsigned long long)MASK_ULONG);
  return (unsigned long)(val & (unsigned long long)MASK_ULONG);
}

/** Unsigned long long to unsigned int */
inline unsigned int ulltoui(unsigned long long val) {
  assert(val <= (unsigned long long)MASK_UINT);
  return (unsigned int)(val & (unsigned long long)MASK_UINT);
}

/** Unsigned long long to unsigned short */
inline unsigned short ulltous(unsigned long long val) {
  assert(val <= (unsigned long long)MASK_USHORT);
  return (unsigned short)(val & (unsigned long long)MASK_USHORT);
}

/** Unsigned size_t to unsigned long */
inline unsigned long ustoul(size_t val) {
  assert(val <= (size_t)MASK_ULONG);
  return (unsigned long)(val & (size_t)MASK_ULONG);
}

/** Unsigned size_t to unsigned int */
inline unsigned int ustoui(size_t val) {
  assert(val <= (size_t)MASK_UINT);
  return (unsigned int)(val & (size_t)MASK_UINT);
}

/** Unsigned size_t to unsigned short */
inline unsigned short ustous(size_t val) {
  assert(val <= (size_t)MASK_USHORT);
  return (unsigned short)(val & (size_t)MASK_USHORT);
}

/** Signed long to signed int */
inline int sltoi(long val) {
  assert(val >= 0);
#if INT_MAX < LONG_MAX
  assert((unsigned long)val <= (unsigned long)INT_MAX);
#endif
  return (int)(val & (long)MASK_SINT);
}

/** Singed long to unsigned int */
inline unsigned int sltoui(long val) {
  assert(val >= 0);
#if UINT_MAX < LONG_MAX
  assert((unsigned long)val <= (unsigned long)MASK_UINT);
#endif
  return (unsigned int)(val & (long)MASK_UINT);
}

/** Signed long to signed short */
inline short sltos(long val) {
  assert(val >= 0);
  assert((unsigned long)val <= (unsigned long)MASK_SSHORT);
  return (short)(val & (long)MASK_SSHORT);
}

/** Signed long to unsigned short */
inline unsigned short sltous(long val) {
  assert(val >= 0);
  assert((unsigned long)val <= (unsigned long)MASK_USHORT);
  return (unsigned short)(val & (long)MASK_USHORT);
}

/** Unsigned long long to signed long long */
inline long long ulltoll(unsigned long long val) {
  assert(val <= (unsigned long long)MASK_SLONGLONG);
  return (long long)(val & (unsigned long long)MASK_SLONGLONG);
}

/** Unsigned long long to signed long */
inline long ulltol(unsigned long long val) {
  assert(val <= (unsigned long long)MASK_SLONG);
  return (long)(val & (unsigned long long)MASK_SLONG);
}

/** Unsigned long long to signed int */
inline int ulltoi(unsigned long long val) {
  assert(val <= (unsigned long long)MASK_SINT);
  return (int)(val & (unsigned long long)MASK_SINT);
}

/** Signed long long to signed long */
inline long slltol(long long val) {
  assert(val >= 0);
  assert((unsigned long long)val <= (unsigned long long)MASK_SLONG);
  return (long)(val & (long long)MASK_SLONG);
}

/** Signed long long to signed int */
inline int slltoi(long long val) {
  assert(val >= 0);
  assert((unsigned long long)val <= (unsigned long long)MASK_SINT);
  return (int)(val & (long long)MASK_SINT);
}

/** Signed long long to signed short */
inline short slltos(long long val) {
  assert(val >= 0);
  assert((unsigned long long)val <= (unsigned long long)MASK_SSHORT);
  return (short)(val & (long long)MASK_SSHORT);
}

/** size_t to ssize_t */
inline ssize_t ssztosz(size_t val) {
  assert(val <= (size_t)MASK_SSIZE_T);
  return (ssize_t)(val & (size_t)MASK_SSIZE_T);
}

/** size_t to int */
inline int sztoi(size_t val) {
  assert(val <= (size_t)MASK_SINT);
  return (int)(val & (size_t)MASK_SINT);
}

/** size_t to short */
inline short sztos(size_t val) {
  assert(val <= (size_t)MASK_SSHORT);
  return (short)(val & (size_t)MASK_SSHORT);
}

/** ssize_t to unsigned int */
inline unsigned int ssztoui(ssize_t val) {
  assert(val >= 0);
#if UINT_MAX < SSIZE_MAX
  assert(val <= (ssize_t)MASK_UINT);
#endif
  return (unsigned int)(val & (ssize_t)MASK_UINT);
}

/** ssize_t to unsigned short */
inline unsigned short ssztous(ssize_t val) {
  assert(val >= 0);
#if USHRT_MAX < SSIZE_MAX
  assert(val <= (ssize_t)MASK_USHORT);
#endif
  return (unsigned short)(val & (ssize_t)MASK_USHORT);
}
