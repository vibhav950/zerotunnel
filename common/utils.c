#include "defines.h"

#include <limits.h>

#define MASK_UCHAR ((unsigned char)~0)
#define MASK_SCHAR (MASK_UCHAR >> 1)

#define MASK_USHORT ((unsigned short)~0)
#define MASK_SSHORT (MASK_USHORT >> 1)

#define MASK_UINT ((unsigned int)~0)
#define MASK_SINT (MASK_UINT >> 1)

#define MASK_ULONG ((unsigned long)~0)
#define MASK_SLONG (MASK_ULONG >> 1)

#define MASK_ULONGLONG ((unsigned long long)~0)
#define MASK_SLONGLONG (MASK_ULONGLONG >> 1)

#define MASK_USIZE_T ((size_t)~0)
#define MASK_SSIZE_T (MASK_USIZE_T >> 1)

inline unsigned short zt_ultous(unsigned long val) {
  ASSERT(val <= (unsigned long)MASK_USHORT);
  return (unsigned short)(val & (unsigned long)MASK_USHORT);
}

inline unsigned char zt_ultouc(unsigned long val) {
  ASSERT(val <= (unsigned long)MASK_UCHAR);
  return (unsigned char)(val & (unsigned long)MASK_UCHAR);
}

inline unsigned long zt_ulltoul(unsigned long long val) {
  ASSERT(val <= (unsigned long long)MASK_ULONG);
  return (unsigned long)(val & (unsigned long long)MASK_ULONG);
}

inline unsigned int zt_ulltoui(unsigned long long val) {
  ASSERT(val <= (unsigned long long)MASK_UINT);
  return (unsigned int)(val & (unsigned long long)MASK_UINT);
}

inline unsigned short zt_ulltous(unsigned long long val) {
  ASSERT(val <= (unsigned long long)MASK_USHORT);
  return (unsigned short)(val & (unsigned long long)MASK_USHORT);
}

inline unsigned long zt_ustoul(size_t val) {
  ASSERT(val <= (size_t)MASK_ULONG);
  return (unsigned long)(val & (size_t)MASK_ULONG);
}

inline unsigned int zt_ustoui(size_t val) {
  ASSERT(val <= (size_t)MASK_UINT);
  return (unsigned int)(val & (size_t)MASK_UINT);
}

inline unsigned short zt_ustous(size_t val) {
  ASSERT(val <= (size_t)MASK_USHORT);
  return (unsigned short)(val & (size_t)MASK_USHORT);
}

inline int zt_sltoi(long val) {
  ASSERT(val >= 0);
#if INT_MAX < LONG_MAX
  ASSERT((unsigned long)val <= (unsigned long)INT_MAX);
#endif
  return (int)(val & (long)MASK_SINT);
}

inline unsigned int zt_sltoui(long val) {
  ASSERT(val >= 0);
#if UINT_MAX < LONG_MAX
  ASSERT((unsigned long)val <= (unsigned long)MASK_UINT);
#endif
  return (unsigned int)(val & (long)MASK_UINT);
}

inline short zt_sltos(long val) {
  ASSERT(val >= 0);
  ASSERT((unsigned long)val <= (unsigned long)MASK_SSHORT);
  return (short)(val & (long)MASK_SSHORT);
}

inline unsigned short zt_sltous(long val) {
  ASSERT(val >= 0);
  ASSERT((unsigned long)val <= (unsigned long)MASK_USHORT);
  return (unsigned short)(val & (long)MASK_USHORT);
}

inline long long zt_ulltoll(unsigned long long val) {
  ASSERT(val <= (unsigned long long)MASK_SLONGLONG);
  return (long long)(val & (unsigned long long)MASK_SLONGLONG);
}

inline long zt_ulltol(unsigned long long val) {
  ASSERT(val <= (unsigned long long)MASK_SLONG);
  return (long)(val & (unsigned long long)MASK_SLONG);
}

inline int zt_ulltoi(unsigned long long val) {
  ASSERT(val <= (unsigned long long)MASK_SINT);
  return (int)(val & (unsigned long long)MASK_SINT);
}

inline long zt_slltol(long long val) {
  ASSERT(val >= 0);
  ASSERT((unsigned long long)val <= (unsigned long long)MASK_SLONG);
  return (long)(val & (long long)MASK_SLONG);
}

inline int zt_slltoi(long long val) {
  ASSERT(val >= 0);
  ASSERT((unsigned long long)val <= (unsigned long long)MASK_SINT);
  return (int)(val & (long long)MASK_SINT);
}

inline short zt_slltos(long long val) {
  ASSERT(val >= 0);
  ASSERT((unsigned long long)val <= (unsigned long long)MASK_SSHORT);
  return (short)(val & (long long)MASK_SSHORT);
}

inline ssize_t zt_ssztosz(size_t val) {
  ASSERT(val <= (size_t)MASK_SSIZE_T);
  return (ssize_t)(val & (size_t)MASK_SSIZE_T);
}

inline int zt_sztoi(size_t val) {
  ASSERT(val <= (size_t)MASK_SINT);
  return (int)(val & (size_t)MASK_SINT);
}

inline short zt_sztos(size_t val) {
  ASSERT(val <= (size_t)MASK_SSHORT);
  return (short)(val & (size_t)MASK_SSHORT);
}

inline unsigned int zt_ssztoui(ssize_t val) {
  ASSERT(val >= 0);
#if UINT_MAX < SSIZE_MAX
  ASSERT(val <= (ssize_t)MASK_UINT);
#endif
  return (unsigned int)(val & (ssize_t)MASK_UINT);
}

inline unsigned short zt_ssztous(ssize_t val) {
  ASSERT(val >= 0);
#if USHRT_MAX < SSIZE_MAX
  ASSERT(val <= (ssize_t)MASK_USHORT);
#endif
  return (unsigned short)(val & (ssize_t)MASK_USHORT);
}

uint64_t zt_filesize_unit_conv(uint64_t size) {
  if (size > SIZE_TB)
    return size / SIZE_TB;
  else if (size > SIZE_GB)
    return size / SIZE_GB;
  else if (size > SIZE_MB)
    return size / SIZE_MB;
  else if (size > SIZE_KB)
    return size / SIZE_KB;
  else
    return size; /* in bytes */
}

const char *zt_filesize_unit_str(uint64_t size) {
  if (size > SIZE_TB)
    return "TB";
  else if (size > SIZE_GB)
    return "GB";
  else if (size > SIZE_MB)
    return "MB";
  else if (size > SIZE_KB)
    return "KB";
  else
    return "B"; /* in bytes */
}