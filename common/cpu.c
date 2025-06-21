#define _GNU_SOURCE

#include "defines.h"

#if defined(_WIN32)
#define _PLATFORM_WIN32
#include <Windows.h>
#elif defined(__linux__)
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#define _PLATFORM_LINUX
#elif defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#if TARGET_OS_MAC == 1
#include <sys/sysctl.h>
#include <sys/types.h>
#define _PLATFORM_OSX
#endif
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#include <sys/types.h>
#define _PLATFORM_BSD
#endif

#define SINGLE_PROCESSOR 1

// clang-format off
/**
 * References:
 * [1] https://github.com/GNOME/glib/blob/main/glib/gthread.c#L1130-L1208
 * [2] https://github.com/AmanoTeam/Nouzen/blob/master/src/os/cpu.c
 * [3] https://bugs.python.org/issue17444
 * [4] https://learn.microsoft.com/en-us/windows/win32/api/processtopologyapi/nf-processtopologyapi-getprocessgroupaffinity
 * [5] https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getactiveprocessorcount
 */
// clang-format on

unsigned int zt_cpu_get_processor_count(void) {
#if defined(_PLATFORM_WIN32)
  /**
   * This method should also work systems with greater than 64 processors where
   * a processor may be scheduled to processors from multiple processor groups.
   * For more info, see
   * https://learn.microsoft.com/en-us/windows/win32/procthread/processor-groups
   */
  HANDLE hProc = GetCurrentProcess();
  USHORT nGroups = 0;
  PUSHORT arrGroups = NULL;
  unsigned int nprocs = 0;
  (void)GetProcessGroupAffinity(hProc, &nGroups, NULL);
  arrGroups = (PUSHORT)malloc(nGroups * sizeof(USHORT));
  if (!arrGroups)
    return SINGLE_PROCESSOR;
  if (!GetProcessGroupAffinity(hProc, &nGroups, arrGroups)) {
    free(arrGroups);
    return SINGLE_PROCESSOR;
  }
  for (USHORT i = 0; i < nGroups; ++i)
    nprocs += GetActiveProcessorCount(arrGroups[i]);
  free(arrGroups);
  return nprocs;
#elif defined(_PLATFORM_LINUX)
  int nprocs = MIN(sysconf(_SC_NPROCESSORS_ONLN), CPU_SETSIZE);
  int af_count = 0, err;
  unsigned int count;
  cpu_set_t cpu_mask;
  CPU_ZERO(&cpu_mask);
  err = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_mask);
  if (!err)
    af_count = CPU_COUNT(&cpu_mask);
  /* prefer affinity-based result, if available */
  count = (af_count > 0) ? af_count : nprocs;
  return count;
#elif defined(_PLATFORM_OSX) || defined(_PLATFORM_BSD)
#if defined(_PLATFORM_OSX)
  int mib[] = {CTL_HW, HW_AVAILCPU};
#else
  const int mib[] = {CTL_HW, HW_NCPU};
#endif
  unsigned int count;
  size_t size = sizeof(count);
  if ((sysctl(mib, 2, &count, &size, NULL, 0) == 0) && (count > 0))
    return count;
#endif
  return SINGLE_PROCESSOR; /* fallback */
}
