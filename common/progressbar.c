#include "progressbar.h"
#include "defines.h"
#include "log.h"
#include "time_utils.h"

#include <float.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define SIZE_KB ((size_t)1024)   /* 1 KB */
#define SIZE_MB (1024 * SIZE_KB) /* 1 MB */
#define SIZE_GB (1024 * SIZE_MB) /* 1 GB */

/** Fixed progressbar element sizes */
enum PB_ELEMENT_SIZES {
  PB_FILE_NAME_SIZE = 32 + 1,
  PB_RECIPIENT_NAME_SIZE = 32 + 1,
  // xxx%, space
  PB_PERCENT_SIZE = 4 + 1,
  // xxx.xxX, space
  PB_DATA_SIZE = (3 + 1 + 2 + 1 + 1),
  PB_THROUGHPUT_SIZE = (3 + 1 + 2 + 3 + 1),
  PB_ETA_SIZE = (2 + 1 + 2 + 1 + 2 + 1), // hh:mm:ss, space
  PB_METER_SIZE = 44 + 1,
};

enum PB_SCREEN_WIDTH {
  PB_MIN_SCREEN_WIDTH = 80,
  PB_MIN_LINE1_WIDTH =
      (PB_FILE_NAME_SIZE + PB_DATA_SIZE + PB_RECIPIENT_NAME_SIZE + 1),
  PB_MIN_LINE2_WIDTH = (PB_DATA_SIZE + PB_PERCENT_SIZE + PB_THROUGHPUT_SIZE +
                        PB_ETA_SIZE + PB_METER_SIZE + 1),
};

enum {
  PB_THREAD_REFRESH_INTERVAL = 500000UL, // 500ms (in us)
};

typedef struct _progressbar_st {
  pthread_mutex_t lock;
  char progress[PB_METER_SIZE - 2]; /* buffer for progress meter chars */
  char *spaces;                     /* buffer for whitespace chars */
  int width;            /* previously recorded window width (columns) */
  volatile bool redraw; /* redraw entire progressbar on next update */
  bool after_log;       /* next redraw occurs after a log */
  char file_name[PB_FILE_NAME_SIZE];
  char recipient_name[PB_RECIPIENT_NAME_SIZE];
  size_t total_size;
  volatile size_t xferd_size;
  zt_timeval_t start_time;
} progressbar_t;

static progressbar_t *progressbar;
static pthread_t g_pb_thread;
static volatile atomic_bool terminate_thread;
static volatile sig_atomic_t winsize_changed;
static volatile atomic_bool dont_update;

/**
 * Get a readable representation of the data size in bytes.
 * The displayed format is `aaa.bb{B,K,M,G}`.
 */
static const char *pb_datavalue_readable(size_t bytes) {
  static char buf[PB_DATA_SIZE];

  if (bytes > 0 && bytes <= 999)
    snprintf(buf, PB_DATA_SIZE, "%6.2fB", (double)bytes);
  else if (bytes <= 999 * SIZE_KB)
    snprintf(buf, PB_DATA_SIZE, "%6.2fK", (double)bytes / SIZE_KB);
  else if (bytes <= 999 * SIZE_MB)
    snprintf(buf, PB_DATA_SIZE, "%6.2fM", (double)bytes / SIZE_MB);
  else if (bytes <= 999 * SIZE_GB)
    snprintf(buf, PB_DATA_SIZE, "%6.2fG", (double)bytes / SIZE_GB);
  else
    snprintf(buf, PB_DATA_SIZE, "---.--B");
  return (const char *)buf;
}

/**
 * Get a readable representation of the data transfer rate given in B/s.
 * The displayed format is `aaa.bb{B,K,M,G}/s`.
 */
static const char *pb_throughput_readable(size_t rate) {
  static char buf[PB_THROUGHPUT_SIZE];

  if (rate > 0 && rate <= 999)
    snprintf(buf, PB_THROUGHPUT_SIZE, "%6.2fB/s", (double)rate);
  else if (rate <= 999 * SIZE_KB)
    snprintf(buf, PB_THROUGHPUT_SIZE, "%6.2fK/s", (double)rate / SIZE_KB);
  else if (rate <= 999 * SIZE_MB)
    snprintf(buf, PB_THROUGHPUT_SIZE, "%6.2fM/s", (double)rate / SIZE_MB);
  else if (rate <= 999 * SIZE_GB)
    snprintf(buf, PB_THROUGHPUT_SIZE, "%6.2fG/s", (double)rate / SIZE_GB);
  else
    snprintf(buf, PB_THROUGHPUT_SIZE, "---.--B/s");
  return (const char *)buf;
}

#define SECONDS_PER_MINUTE ((size_t)60)
#define SECONDS_PER_HOUR (60 * SECONDS_PER_MINUTE)

/**
 * Get a readable representation of the time, given the time value in seconds.
 * The displayed time is of the format `hh:mm:ss`.
 */
static const char *pb_eta_readable(timediff_t seconds) {
  static char buf[PB_ETA_SIZE];
  int hh, mm, ss;

  if (seconds > 23 * SECONDS_PER_HOUR + 59 * SECONDS_PER_MINUTE + 59) {
    snprintf(buf, PB_ETA_SIZE, "--:--:--");
    return (const char *)buf;
  }
  hh = seconds / SECONDS_PER_HOUR;
  mm = (seconds % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
  ss = seconds % SECONDS_PER_MINUTE;
  snprintf(buf, PB_ETA_SIZE, "%02d:%02d:%02d", hh, mm, ss);
  return (const char *)buf;
}

static inline ATTRIBUTE_ALWAYS_INLINE int pb_get_screen_width(void) {
  struct winsize ws;

  if (!ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws))
    return ws.ws_col;
  return PB_MIN_SCREEN_WIDTH;
}

static inline ATTRIBUTE_ALWAYS_INLINE void pb_save_cursor(void) {
  // `ESC 7`: save cursor position
  fputs("\0337", stdout);
  fflush(stdout);
}

static inline ATTRIBUTE_ALWAYS_INLINE void pb_restore_cursor(void) {
  // `ESC 8`: restore cursor position
  fputs("\0338", stdout);
  fflush(stdout);
}

static inline ATTRIBUTE_ALWAYS_INLINE bool
pb_handle_winsize_change(bool force) {
  ASSERT(progressbar);

  /* Check if the window size has changed;
    if yes, we have to redraw the progressbar */
  if (unlikely(winsize_changed | force)) { // yes this is a BITWISE OR
    int width, oldwidth;
    char *spaces;

    oldwidth = force ? 0 : progressbar->width;
    width = pb_get_screen_width();
    width = MAX(width, PB_MIN_SCREEN_WIDTH);
    if (likely(width > oldwidth)) {
      spaces = malloc(width + 1);
      if (unlikely(!spaces)) {
        winsize_changed = false; // XXX: should we try again next update?
        return false; /* we couldn't allocate memory, use the old size */
      }
      if (likely(progressbar->spaces))
        free(progressbar->spaces);
      memset(spaces, ' ', width);
      spaces[width] = '\0';
    } else {
      spaces = progressbar->spaces;
    }
    progressbar->width = width;
    progressbar->spaces = spaces;
    progressbar->redraw = true; /* redraw with new dimensions on next update */
    winsize_changed = false;
    return true;
  }
  return false;
}

static inline ATTRIBUTE_ALWAYS_INLINE void pb_clear_progressbar(void) {
  ASSERT(progressbar);
  /* We are currently (during updates / completion) at the end of the second
     progress bar line. We want to:
     1. Clear first line (file/recipient info)
     2. Clear second line (meter)
     3. Delete the (now empty) second line so all following output scrolls up
        by one line
     4. Leave cursor at start of the (former) first line so normal printing
        continues there. */
  /* Sequence explanation:
     ESC [1A : move cursor up 1 line (to first line)
     ESC [1G : move to column 1
     ESC [2K : clear entire line
     ESC [1B : move down 1 line (second line)
     ESC [1G : column 1
     ESC [2K : clear entire line
     ESC [1M : delete this line (pull lines below up)
     ESC [1A : move cursor up to the cleared first line position
     ESC [1G : ensure column 1 */
  fputs("\x1B[1A\x1B[1G\x1B[2K\x1B[1B\x1B[1G\x1B[2K\x1B[1M\x1B[1A\x1B[1G",
        stdout);
  fflush(stdout);
}

static void pb_progressbar_update(void) {
  char *spaces;
  float perc;
  size_t nbytes, throughput, estimate;
  int nslots, empty, width;
  timediff_t elapsed;

  ASSERT(progressbar);

  if (unlikely(atomic_load_explicit(&dont_update, memory_order_acquire)))
    return;

  pthread_mutex_lock(&progressbar->lock);
  (void)pb_handle_winsize_change(false);

  spaces = progressbar->spaces;
  width = progressbar->width;

  if (progressbar->redraw) {
    if (!progressbar->after_log) {
      /* Normal redraw: clear previous two progress bar lines */
      fputs("\x1B[1G\x1B[0J\x1B[1A\x1B[0J", stdout);
    } else {
      /* Redraw after a log: we already cleared lines before logging; do not
       * clear the log line above */
      fputs("\x1B[1G\x1B[0J", stdout); /* just clean current line */
    }
    /* Print the first line (right-align recipient name) */
    {
      const char *filename = progressbar->file_name;
      const char *recipient = progressbar->recipient_name;
      empty = MAX(width - (int)(PB_DATA_SIZE + strlen(filename) +
                                strlen(recipient) + 4),
                  1); /* 3 spaces */
      // clang-format off
      fprintf(stdout, " %s %s %.*s %s \n",
              filename,
              pb_datavalue_readable(progressbar->total_size),
              empty,
              spaces,
              recipient
      );
      // clang-format on
    }
    progressbar->after_log = false; /* consumed */
    progressbar->redraw = false;
  }

  nbytes = progressbar->xferd_size;
  perc = MIN((float)nbytes / (float)progressbar->total_size, 1.0f);
  nslots = (int)(perc * (PB_METER_SIZE - 3));
  empty = PB_METER_SIZE - 3 - nslots;

  elapsed = zt_timediff_msec(zt_time_now(), progressbar->start_time) / 1000;
  throughput = (elapsed != 0) ? nbytes / elapsed : 0;
  estimate =
      (throughput != 0) ? (progressbar->total_size - nbytes) / throughput : 0;

  // clang-format off
  /* Print the second line with progress bar */
  fprintf(stdout, "\x1B[1G %s %3d%% %.*s [%.*s%.*s] %s %s",
          pb_datavalue_readable(nbytes),
          (int)(perc * 100),
          MAX(0, width - PB_MIN_LINE2_WIDTH - 1),
          spaces,
          nslots,
          progressbar->progress,
          empty,
          spaces,
          pb_throughput_readable(throughput),
          pb_eta_readable(estimate)
  );
  // clang-format on
  fflush(stdout);
  pthread_mutex_unlock(&progressbar->lock);
}

static void *pb_update_thread(void *args ATTRIBUTE_UNUSED) {
  while (!atomic_load_explicit(&terminate_thread, memory_order_relaxed)) {
    pb_progressbar_update();
    usleep(PB_THREAD_REFRESH_INTERVAL);
  }
  return NULL;
}

static void pb_log_before_cb(void *args ATTRIBUTE_UNUSED) {
  /* Pause updates and clear progress bar so logs print at former first line */
  atomic_store_explicit(&dont_update, true, memory_order_release);
  if (!progressbar)
    return;
  pthread_mutex_lock(&progressbar->lock);
  pb_clear_progressbar();
  pthread_mutex_unlock(&progressbar->lock);
}

static void pb_log_after_cb(void *args ATTRIBUTE_UNUSED) {
  if (!progressbar) {
    atomic_store_explicit(&dont_update, false, memory_order_release);
    return;
  }
  /* Move to a new line, mark for redraw below logs, then resume updates */
  fputc('\n', stdout);
  pthread_mutex_lock(&progressbar->lock);
  progressbar->redraw = true;
  progressbar->after_log = true;
  pthread_mutex_unlock(&progressbar->lock);
  atomic_store_explicit(&dont_update, false, memory_order_release);
}

int zt_progressbar_init(void) {
  if (progressbar)
    return 0;

  progressbar = calloc(1, sizeof(progressbar_t));
  if (!progressbar)
    return -1;

  atomic_store(&terminate_thread, false);

  if (pthread_mutex_init(&progressbar->lock, NULL)) {
    free(progressbar);
    progressbar = NULL;
    return -1;
  }

  /* Get the screen width; subsequent resizes will
    be handled on arrival of a SIGWINCH signal */
  if (!pb_handle_winsize_change(true)) {
    pthread_mutex_destroy(&progressbar->lock);
    free(progressbar);
    progressbar = NULL;
    return -1; /* out of memory */
  }

  memset(progressbar->progress, '=', PB_METER_SIZE - 3);
  progressbar->progress[PB_METER_SIZE - 3] = '\0';

  memset(progressbar->recipient_name, ' ', PB_RECIPIENT_NAME_SIZE - 1);
  progressbar->recipient_name[PB_RECIPIENT_NAME_SIZE - 1] = '\0';

  memset(progressbar->file_name, ' ', PB_FILE_NAME_SIZE - 1);
  progressbar->file_name[PB_FILE_NAME_SIZE - 1] = '\0';

  (void)zt_logger_append_before_cb(NULL, pb_log_before_cb, NULL);
  (void)zt_logger_append_after_cb(NULL, pb_log_after_cb, NULL);

  atomic_store(&dont_update, true);
  if (pthread_create(&g_pb_thread, NULL, pb_update_thread, NULL)) {
    pthread_mutex_destroy(&progressbar->lock);
    free(progressbar->spaces);
    free(progressbar);
    progressbar = NULL;
    return -1;
  }
  return 0;
}

void zt_progressbar_destroy(void) {
  if (progressbar) {
    pthread_mutex_lock(&progressbar->lock);
    atomic_store_explicit(&terminate_thread, true, memory_order_release);
    pthread_mutex_unlock(&progressbar->lock);
    pthread_join(g_pb_thread, NULL);
    pthread_mutex_destroy(&progressbar->lock);
    zt_logger_remove_before_cb(NULL, pb_log_before_cb);
    zt_logger_remove_after_cb(NULL, pb_log_after_cb);
    free(progressbar->spaces);
    free(progressbar);
    progressbar = NULL;
    atomic_store(&terminate_thread, false);
  }
}

void zt_progressbar_begin(const char *recipient, const char *filename,
                          size_t filesize) {
  if (progressbar) {
    pthread_mutex_lock(&progressbar->lock);

    if (recipient) {
      strncpy(progressbar->recipient_name, recipient,
              PB_RECIPIENT_NAME_SIZE - 1);
      progressbar->recipient_name[PB_RECIPIENT_NAME_SIZE - 1] = '\0';
    }

    if (filename) {
      strncpy(progressbar->file_name, filename, PB_FILE_NAME_SIZE - 1);
      progressbar->file_name[PB_FILE_NAME_SIZE - 1] = '\0';
    }

    progressbar->total_size = (filesize > 0) ? filesize : 1;
    progressbar->xferd_size = 0;
    progressbar->start_time = zt_time_now();
    progressbar->redraw = true;     /* redraw on next update */
    progressbar->after_log = false; /* start fresh */
    atomic_store_explicit(&dont_update, false, memory_order_release);
    pthread_mutex_unlock(&progressbar->lock);
  }
}

void zt_progressbar_update(size_t nbytes) {
  if (likely(progressbar))
    progressbar->xferd_size += nbytes;
}

void zt_progressbar_winsize_changed(int signal ATTRIBUTE_UNUSED) {
  winsize_changed = true;
}

void zt_progressbar_complete(void) {
  if (likely(progressbar)) {
    pthread_mutex_lock(&progressbar->lock);
    pb_clear_progressbar();
    atomic_store_explicit(&dont_update, true, memory_order_release);
    pthread_mutex_unlock(&progressbar->lock);
  }
}
