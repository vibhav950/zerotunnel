#include "defines.h"

#if defined(_WIN32)
#define __platform_type 1
#include <Windows.h>
#elif defined(__linux__)
#include <unistd.h>
#define __platform_type 2
#elif defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#if TARGET_OS_MAC == 1
/* OSX */
#include <unistd.h>
#define __platform_type 3
#endif
#endif

#if __platform_type == 1
int CountSetBits(ULONG_PTR bitMask) {
  DWORD LSHIFT = sizeof(ULONG_PTR) * 8 - 1;
  DWORD bitSetCount = 0;
  ULONG_PTR bitTest = (ULONG_PTR)1 << LSHIFT;
  DWORD i;

  for (i = 0; i <= LSHIFT; ++i) {
    bitSetCount += ((bitMask & bitTest) ? 1 : 0);
    bitTest /= 2;
  }

  return (int)bitSetCount;
}
#endif

inline int zt_cpu_get_processor_count(void) {
#if __platform_type == 1
  SYSTEM_LOGICAL_PROCESSOR_INFORMATION *info = NULL;
  DWORD length = 0;
  int nprocessors, i;

  (void)GetLogicalProcessorInformation(NULL, &length);
  info = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION *)malloc(length);
  if (!info)
    return -1;
  if (!GetLogicalProcessorInformation(info, &length)) {
    free(info);
    return -1;
  }
  for (i = 0;, nprocessors = 0,
      i < length/sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
       ++i) {
    if (info[i].Relationship == RelationProcessorCore)
      nprocessors += CountSetBits(info[i].ProcessorMask);
  }
  free(info);
  return nprocessors;
#elif (__platform_type == 2) || (__platform_type == 3)
  long nprocessors = sysconf(_SC_NPROCESSORS_ONLN);
  return (int)((nprocessors > 0) ? nprocessors : -1);
#else
  return -1;
#endif
}
