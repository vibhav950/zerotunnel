#ifndef __TIMEOUT_H__
#define __TIMEOUT_H__

#include "time_utils.h"

/* ======================= utilities for spinlocks ======================= */

#if defined(_WIN32)
#include <Windows.h> // SwitchToThread(), Sleep()
#include <intrin.h>  // _mm_pause()
#else                /* Linux, OSX, BSD; all have this header */
#include <sched.h>   // sched_yield()
#endif

// FIXME: these conditions need to be reviewed
#if ((defined(__GNUC__) && !defined(__clang__)) &&                             \
     (defined(__i386__) || defined(__x86_64__))) ||                            \
    (defined(__has_builtin) && __has_builtin(__builtin_ia32_pause))
#define spin_pause() __builtin_ia32_pause()
#elif defined(__x86_64__) || defined(__i386__) || defined(__amd64__) ||        \
    defined(_M_X64) || defined(_M_IX86)
#if defined(_MSC_VER)
// FIXME: better way to do this on MSVC without pulling <intrin.h>?
#define spin_pause() _mm_pause()
#else
#define spin_pause()                                                           \
  do {                                                                         \
    __asm__ volatile("pause");                                                 \
    __asm__ volatile("" ::: "memory");                                         \
  } while (0)
#endif
#else
#error "unknown platform"
#endif

/**
 * spin_yield()
 * @brief Attempt to make this thread relinquish the processor
 *
 * - On Linux, `sched_yield()` always succeeds so there is nothing we can do
 *   instead if there are no other threads waiting on the current processor
 *
 * - On Windows, we sleep for 1ms to try saving power if execution is not
 *   switched to another thread
 */

#if defined(_WIN32)
#define spin_yield()                                                           \
  do {                                                                         \
    if (SwitchToThread() == 0)                                                 \
      Sleep(1);                                                                \
  } while (0)
#else
#define spin_yield() sched_yield()
#endif

/**
 * decaying_sleep(pause, pause32)
 * @brief Sleep with an exponential/multiplicative backoff
 *
 * This macro is a little misleading in that it doesn't always actually "sleep".
 * Instead, it gradually shifts from short (less) pauses to longer (more) pauses
 * to finally `yield`ing the processor on each spin. In theory this should
 * adjust the busy-wait for both short and long waiting periods, where the
 * thread doesn't steal and burn resources from other threads waiting on the
 * same processor.
 *
 * Reference: https://github.com/gstrauss/plasma/blob/master/plasma_spin.c
 */
#define decaying_sleep(pause, pause32)                                         \
  do {                                                                         \
    if (likely(pause)) {                                                       \
      spin_pause();                                                            \
      pause--;                                                                 \
    } else if (likely(pause32)) {                                              \
      int i = 4;                                                               \
      do {                                                                     \
        spin_pause();                                                          \
        spin_pause();                                                          \
        spin_pause();                                                          \
        spin_pause();                                                          \
        spin_pause();                                                          \
        spin_pause();                                                          \
        spin_pause();                                                          \
        spin_pause();                                                          \
      } while (--i);                                                           \
      pause32--;                                                               \
    } else {                                                                   \
      spin_yield();                                                            \
    }                                                                          \
  } while (0)

/* ======================================================================= */

typedef void (*timeout_cb)(void *args);

typedef struct _zt_timeout_st {
  zt_timeval_t begin;
  timediff_t expire_in_usec;
  timeout_cb handler;
} zt_timeout_t;

/**
 * Set a timeout now
 */
void zt_timeout_begin(zt_timeout_t *timeout, timediff_t usec,
                      timeout_cb handler);

/**
 * Reset the timeout
 *
 * This function should only be called after a timeout has already been set
 * using zt_timeout_begin()
 */
void zt_timeout_reset(zt_timeout_t *timeout);

/**
 * Check if the timeout has expired
 *
 * This function should only be called after a timeout has already been set
 * using zt_timeout_begin()
 *
 * Returns 1 if the timeout has expired, 0 otherwise
 */
int zt_timeout_expired(zt_timeout_t *timeout, void *args);

#endif /* __TIMEOUT_H__ */
