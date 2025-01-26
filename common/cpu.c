#include "defs.h"

#if defined(_WIN32)
#define __platform_type 1
#include <windows.h>
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

inline int cpu_get_processor_count(void) {
#if __platform_type == 1
  SYSTEM_LOGICAL_PROCESSOR_INFORMATION *info = NULL;
  DWORD length = 0;
  int physical_cores = 0;
  int count = length / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);

  GetLogicalProcessorInformation(NULL, &length);
  info = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION *)malloc(length);
  if (!info)
    return -1;
  if (!GetLogicalProcessorInformation(info, &length)) {
    free(info);
    return -1;
  }
  for (; count; --count)
    if (info[i].Relationship == RelationProcessorCore)
      physical_cores++;
  free(info);
  return physical_cores;
#elif (__platform_type == 2) || (__platform_type == 3)
  long cores = sysconf(_SC_NPROCESSORS_ONLN);
  return (int)((cores > 0) ? cores : -1);
#else
  return -1;
#endif
}
