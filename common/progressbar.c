/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * progressbar.c
 *
 * Closely based on wget2's progress bar implementation by Tim Ruehsen.
 */

#include "progressbar.h"
#include "defines.h"
#include "log.h"
#include "time_utils.h"

#include <float.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/** Fixed progressbar element sizes */
enum PB_ELEMENT_SIZES {
  PB_FILE_NAME_SIZE = 32 + 1,
  PB_RECIPIENT_NAME_SIZE = 32 + 1,
  // xxx%, space
  PB_PERCENT_SIZE = 4 + 1,
  // xxx.xxX, space
  PB_BYTES_SIZE = (3 + 1 + 2 + 1 + 1),
  PB_SPEED_SIZE = (3 + 1 + 2 + 3 + 1),
  PB_TIME_SIZE = (2 + 1 + 2 + 1 + 2 + 1), // hh:mm:ss, space
  PB_METER_SIZE = 44 + 1,
};

enum PB_SCREEN_WIDTH {
  /* Expanded single line: filename + total_size + xferd_size + percent + progress_meter +
     speed + time + recipient + separators */
  PB_MIN_EXPANDED_LINE_WIDTH =
      (PB_FILE_NAME_SIZE + PB_BYTES_SIZE * 2 + PB_PERCENT_SIZE + PB_METER_SIZE +
       PB_SPEED_SIZE + PB_TIME_SIZE + PB_RECIPIENT_NAME_SIZE + 12),
  /* Compact single line: filename + percent + meter + time + separators */
  PB_MIN_COMPACT_LINE_WIDTH =
      (PB_FILE_NAME_SIZE + PB_PERCENT_SIZE + PB_METER_SIZE + PB_TIME_SIZE + 7),
  PB_MIN_SCREEN_WIDTH = PB_MIN_COMPACT_LINE_WIDTH,
};

enum PB_SETTINGS {
  PB_THREAD_REFRESH_INTERVAL = 500000UL, // 500ms (in us)
  PB_SPEED_RING_SIZE = 30,
};

enum pb_slot_status {
  EMPTY = 0,
  ONGOING = 1,
  DONE = 2,
};

typedef struct _progressbar_slot_st {
  char file_name[PB_FILE_NAME_SIZE];
  char recipient_name[PB_RECIPIENT_NAME_SIZE];
  char total_bytes_buf[PB_BYTES_SIZE];
  char current_bytes_buf[PB_BYTES_SIZE];
  char speed_buf[PB_SPEED_SIZE];
  char time_buf[PB_TIME_SIZE];
  char cdir;
  size_t total_size;
  size_t xferd_size;
  timeval_t start_time;
  timediff_t time_ring[PB_SPEED_RING_SIZE];
  size_t bytes_ring[PB_SPEED_RING_SIZE];
  short ring_idx, ring_used;
  enum pb_slot_status status;
  bool redraw : 1; /* redraw bar on next update */
} progressbar_slot;

typedef struct _progressbar_st {
  progressbar_slot *slots;
  int nslots;
  char progress[PB_METER_SIZE - 2]; /* buffer for progress meter chars */
  char *spaces;                     /* buffer for whitespace chars */
  short width;                      /* last recorded window width (columns) */
  bool redraw;                      /* redraw all slots */
  pthread_t thread;
  pthread_mutex_t lock;
  volatile uintptr_t dont_update;
  zt_logger_t *logger;
} progressbar_t;

static volatile sig_atomic_t winsize_changed;

/**
 * Get a readable representation of the data size in bytes.
 * The displayed format is `aaa.bb{B,K,M,G}`.
 */
static const char *pb_size2str(size_t bytes, char buf[PB_BYTES_SIZE]) {
  if (bytes > 0 && bytes <= 999)
    snprintf(buf, PB_BYTES_SIZE, "%6.2fB", (double)bytes);
  else if (bytes <= 999 * SIZE_KB)
    snprintf(buf, PB_BYTES_SIZE, "%6.2fK", (double)bytes / SIZE_KB);
  else if (bytes <= 999 * SIZE_MB)
    snprintf(buf, PB_BYTES_SIZE, "%6.2fM", (double)bytes / SIZE_MB);
  else if (bytes <= 999 * SIZE_GB)
    snprintf(buf, PB_BYTES_SIZE, "%6.2fG", (double)bytes / SIZE_GB);
  else
    snprintf(buf, PB_BYTES_SIZE, "---.--B");
  return (const char *)buf;
}

/**
 * Get a readable representation of the data transfer rate given in B/s.
 * The displayed format is `aaa.bb{B,K,M,G}/s`.
 */
static const char *pb_speed2str(size_t rate, char buf[PB_SPEED_SIZE]) {
  if (rate > 0 && rate <= 999)
    snprintf(buf, PB_SPEED_SIZE, "%6.2fB/s", (double)rate);
  else if (rate <= 999 * SIZE_KB)
    snprintf(buf, PB_SPEED_SIZE, "%6.2fK/s", (double)rate / SIZE_KB);
  else if (rate <= 999 * SIZE_MB)
    snprintf(buf, PB_SPEED_SIZE, "%6.2fM/s", (double)rate / SIZE_MB);
  else if (rate <= 999 * SIZE_GB)
    snprintf(buf, PB_SPEED_SIZE, "%6.2fG/s", (double)rate / SIZE_GB);
  return (const char *)buf;
}

#define SECONDS_PER_MINUTE ((size_t)60)
#define SECONDS_PER_HOUR (60 * SECONDS_PER_MINUTE)

/**
 * Get a readable representation of the time, given the time value in seconds.
 * The displayed time is of the format `hh:mm:ss`.
 */
static const char *pb_time2str(timediff_t seconds, char buf[PB_TIME_SIZE]) {
  int hh, mm, ss;

  if (seconds > 23 * SECONDS_PER_HOUR + 59 * SECONDS_PER_MINUTE + 59)
    return (const char *)buf;
  hh = seconds / SECONDS_PER_HOUR;
  mm = (seconds % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
  ss = seconds % SECONDS_PER_MINUTE;
  snprintf(buf, PB_TIME_SIZE, "%02d:%02d:%02d", hh, mm, ss);
  return (const char *)buf;
}

static inline ATTRIBUTE_ALWAYS_INLINE int pb_get_screen_width(void) {
  struct winsize ws;

  if (!ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws))
    return ws.ws_col;
  return PB_MIN_SCREEN_WIDTH;
}

static inline ATTRIBUTE_ALWAYS_INLINE void pb_restore_cursor(void) {
  // ESC[u: restore cursor position (SCO)
  fputs("\x1B[u", stdout);
}

static inline ATTRIBUTE_ALWAYS_INLINE void pb_print_slot(const progressbar_t *pb,
                                                         int slot) {
  /*
    ESC[s  : save cursor position (SCO)
    ESC[nA : move cursor up
    ESC[nG : move cursor to column n
  */
  fprintf(stdout, "\x1B[s\x1B[%dA\x1B[1G", pb->nslots - slot);
}

static inline ATTRIBUTE_ALWAYS_INLINE bool pb_update_winsize(progressbar_t *pb,
                                                             bool force) {
  /* We have to redraw all slots if the window size has changed, this may require
   * allocating a larger buffer of whitespace characters. */
  if (unlikely(winsize_changed || force)) {
    short width, oldwidth;
    char *spaces;

    oldwidth = force ? 0 : pb->width;
    width = pb_get_screen_width();
    width = MAX(width, PB_MIN_SCREEN_WIDTH);
    if (likely(width > oldwidth)) {
      // TODO: we can save some memory since not the entire width will be used up by
      // whitespace chars, calculate the max number of characters needed for this width
      spaces = malloc(width + 1);
      if (unlikely(!spaces)) {
        winsize_changed = false; // XXX: should we try again next update?
        return false;            /* we couldn't allocate memory, use the old size */
      }
      if (likely(pb->spaces))
        free(pb->spaces);
      memset(spaces, ' ', width);
      spaces[width] = '\0';
    } else {
      spaces = pb->spaces;
    }
    pb->width = width;
    pb->spaces = spaces;
    pb->redraw = true; /* redraw with new dimensions on next update */
    winsize_changed = false;
    return true;
  }
  return false;
}

/**
 * Calculate an estimate for the current transfer speed and update the ring buffer stats.
 *
 * @param[in] slotp Pointer to the progressbar slot.
 * @return The estimated transfer speed in B/s or SIZE_MAX if there isn't enough data.
 *
 * Transfer speed is computed as the smoothened average of the previous PB_SPEED_RING_SIZE
 * samples stored in the progressbar's ring buffers.
 *
 * This approach is based on wget2's progress bar speed estimation written by Tim Ruehsen.
 * Ref: wget2/libwget/bar.c
 */
static size_t pb_calculate_speed(progressbar_slot *slotp) {
  short ring_idx = slotp->ring_idx;
  short ring_used = slotp->ring_used;
  short next_idx;

  /* Return early if no new data transferred since last sample */
  if (slotp->xferd_size == slotp->bytes_ring[ring_idx])
    return SIZE_MAX;

  if (ring_idx == PB_SPEED_RING_SIZE)
    ring_idx = 0;

  slotp->time_ring[ring_idx] = zt_timediff_msec(zt_time_now(), slotp->start_time);
  slotp->bytes_ring[ring_idx] = slotp->xferd_size;

  if (ring_used < PB_SPEED_RING_SIZE) {
    ring_used++;
    next_idx = 1;
  } else {
    next_idx = ring_idx + 1 == PB_SPEED_RING_SIZE ? 0 : ring_idx + 1;
  }

  slotp->ring_idx = ring_idx;
  slotp->ring_used = ring_used;

  if (ring_used < 2) /* Not enough data to calculate speed */
    return SIZE_MAX;

  size_t bytes = slotp->bytes_ring[ring_idx] - slotp->bytes_ring[next_idx];
  timediff_t time = slotp->time_ring[ring_idx] - slotp->time_ring[next_idx];
  return (bytes * 1000) / (time ? time : 1);
}

static void pb_update_slot(progressbar_t *pb, int slot) {
  progressbar_slot *slotp;
  char *whitespace_chars;
  const char *filename, *recipient;
  float perc;
  size_t nbytes, speed;
  int prgs, empty, width;
  timediff_t elapsed, remaining;

  slotp = &pb->slots[slot];
  if (unlikely(pb->dont_update || slotp->status == EMPTY))
    return;

  whitespace_chars = pb->spaces;
  width = pb->width;

  pb_print_slot(pb, slot);

  filename = slotp->file_name;
  recipient = slotp->recipient_name;

  nbytes = slotp->xferd_size;
  perc = MIN((float)nbytes / (float)slotp->total_size, 1.0f);
  prgs = (int)(perc * (PB_METER_SIZE - 3));
  empty = PB_METER_SIZE - 3 - prgs;

  elapsed = zt_timediff_msec(zt_time_now(), slotp->start_time) / 1000;
  speed = pb_calculate_speed(slotp);
  if (speed == SIZE_MAX)
    remaining = TIMEDIFF_T_MAX;
  else
    remaining = (timediff_t)((slotp->total_size - nbytes) / (speed ? speed : 1));

  // clang-format off
  if (width >= PB_MIN_EXPANDED_LINE_WIDTH) {
    /**
     * Expanded progressbar slot
     *
     * filename - recipient aaa.bbX / aaa.bbX  xxx% [==============================] aaa.bbX/s hh:mm:ss
     *
     * filename          - name of the file being transferred
     * recipient         - name of the sender/recipient
     * aaa.bbX / aaa.bbX - transferred bytes / total size
     * xxx%              - percentage completed
     * hhh:mm:ss         - estimated time remaining
     *
     * Each element has a fixed length and the names are right-aligned or trucated to fit.
     */
    fprintf(stdout, " %s%.*s %c %s%.*s %s / %s%.*s %3d%% [%.*s%.*s] %s %s ",
            filename,
            (PB_FILE_NAME_SIZE - 1) - strlen(filename), /* right-padding for filename element */
            whitespace_chars,
            slotp->cdir,
            recipient,
            (PB_RECIPIENT_NAME_SIZE - 1) - strlen(recipient), /* right-padding for recipient element */
            whitespace_chars,
            pb_size2str(nbytes, slotp->current_bytes_buf),
            pb_size2str(slotp->total_size, slotp->total_bytes_buf),
            pb->width - PB_MIN_EXPANDED_LINE_WIDTH,
            whitespace_chars,
            (int)(perc * 100),
            prgs,
            pb->progress,
            empty,
            whitespace_chars,
            pb_speed2str(speed, slotp->speed_buf),
            pb_time2str(remaining, slotp->time_buf)
    );
  } else {
    /**
     * Compact progressbar slot
     *
     * filename xxx% [==============================] hh:mm:ss
     */
    fprintf(stdout, " %.*s%s %.*s%3d%% [%.*s%.*s] %s ",
            (PB_FILE_NAME_SIZE - 1) - strlen(filename),
            whitespace_chars,
            filename,
            pb->width - PB_MIN_COMPACT_LINE_WIDTH,
            whitespace_chars,
            (int)(perc * 100),
            prgs,
            pb->progress,
            empty,
            whitespace_chars,
            pb_time2str(remaining, slotp->time_buf)
    );
  }
  // clang-format on
  pb_restore_cursor();
  fflush(stdout);
}

static void pb_update(progressbar_t *pb) {
  /* Redraw all slots */
  bool redraw = winsize_changed || pb->redraw;

  pb_update_winsize(pb, false);
  for (int slot = 0; slot < pb->nslots; slot++) {
    if (pb->slots[slot].redraw || redraw) {
      pb_update_slot(pb, slot);
      pb->slots[slot].redraw = false;
    }
  }
}

static void *pb_update_thread(void *args) {
  progressbar_t *pb = (progressbar_t *)args;

  while (pb->dont_update != 4) {
    pthread_mutex_lock(&pb->lock);
    pb_update(pb);
    pthread_mutex_unlock(&pb->lock);
    usleep(PB_THREAD_REFRESH_INTERVAL);
  }
  return NULL;
}

/**
 * Callback hook called before a log line is printed.
 * The log lines appear above the progressbar and the screen is scrolled up if requred.
 */
static void pb_log_before_cb(void *args) {
  progressbar_t *pb = (progressbar_t *)args;

  pthread_mutex_lock(&pb->lock);
  /*
    ESC[s  : save cursor position (SCO)
    ESC[nS : scroll up whole screen
    ESC[nA : move cursor up
    ESC[nG : move cursor to column n
    ESC[0J : clear from cursor until end of screen
  */
  fprintf(stdout, "\x1B[s\x1B[1S\x1B[%dA\x1B[1G\x1B[0J", pb->nslots + 1);
  fflush(stdout);
  pb->dont_update = 3;
  pthread_mutex_unlock(&pb->lock);
}

/**
 * Callback hook called after a log line is printed.
 * The entire progressbar is redrawn below the most recent log line.
 */
static void pb_log_after_cb(void *args) {
  progressbar_t *pb = (progressbar_t *)args;

  pthread_mutex_lock(&pb->lock);
  if (pb->dont_update == 3)
    pb->dont_update = 0;
  pb->redraw = true;
  pb_restore_cursor();
  pb_update(pb);
  pthread_mutex_unlock(&pb->lock);
}

progressbar_t *zt_progressbar_init(progressbar_t *bar, int slots, zt_logger_t *logger) {
  progressbar_t *pb;

  if (slots <= 0)
    return NULL;

  if (bar == NULL) {
    if (!(pb = zt_calloc(1, sizeof(progressbar_t))))
      return NULL;
  } else {
    pb = bar;
    memset(pb, 0, sizeof(*pb));
  }

  /* Get the screen width; subsequent resizes will
    be handled on arrival of a SIGWINCH signal */
  if (!pb_update_winsize(pb, true))
    goto cleanup;

  if (pthread_mutex_init(&pb->lock, NULL))
    goto cleanup;

  /* Don't start updating until at least one slot has begun */
  pb->dont_update = 2;

  if (pthread_create(&pb->thread, NULL, PTRV(pb_update_thread), PTRV(pb)))
    goto cleanup;

  /* Populate progress meters chars */
  memset(pb->progress, '=', PB_METER_SIZE - 3);
  pb->progress[PB_METER_SIZE - 3] = '\0';

  zt_progressbar_set_slots(pb, slots);

  pb->logger = logger;
  (void)zt_logger_append_before_cb(logger, pb_log_before_cb, PTRV(pb));
  (void)zt_logger_append_after_cb(logger, pb_log_after_cb, PTRV(pb));

  return pb;

cleanup:
  pthread_mutex_destroy(&pb->lock);
  pthread_join(pb->thread, NULL);
  if (bar == NULL)
    zt_free(pb);
  return NULL;
}

void zt_progressbar_deinit(progressbar_t *bar) {
  if (bar == NULL)
    return;

  pthread_mutex_lock(&bar->lock);
  bar->dont_update = 4; /* terminate thread loop */
  pthread_mutex_unlock(&bar->lock);

  pthread_join(bar->thread, NULL);
  pthread_mutex_destroy(&bar->lock);

  zt_logger_remove_before_cb(bar->logger, pb_log_before_cb);
  zt_logger_remove_after_cb(bar->logger, pb_log_after_cb);

  if (bar->slots)
    zt_free(bar->slots);

  if (bar->spaces)
    zt_free(bar->spaces);

  memset(bar, 0, sizeof(*bar));
}

void zt_progressbar_free(progressbar_t *bar) {
  if (bar == NULL)
    return;

  zt_progressbar_deinit(bar);
  zt_free(bar);
}

void zt_progressbar_set_slots(progressbar_t *bar, int nslots) {
  if (bar == NULL)
    return;

  pthread_mutex_lock(&bar->lock);
  int more_slots = nslots - bar->nslots;
  if (more_slots > 0) {
    progressbar_slot *new_slots =
        zt_realloc(bar->slots, nslots * sizeof(progressbar_slot));
    if (new_slots == NULL) {
      pthread_mutex_unlock(&bar->lock);
      return;
    }
    bar->slots = new_slots;
    memset(bar->slots + bar->nslots, 0, more_slots * sizeof(progressbar_slot));
    bar->nslots = nslots;

    for (int i = 0; i < more_slots; ++i)
      fputs("\n", stdout);

    pb_update(bar);
  }
  pthread_mutex_unlock(&bar->lock);
}

void zt_progressbar_slot_begin(progressbar_t *bar, int slot, const char *filename,
                               const char *recipient, size_t filesize, bool upload) {
  if (bar == NULL)
    return;

  pthread_mutex_lock(&bar->lock);
  progressbar_slot *slotp = &bar->slots[slot];

  if (recipient)
    strncpy(slotp->recipient_name, recipient, PB_RECIPIENT_NAME_SIZE - 1);

  if (filename)
    strncpy(slotp->file_name, filename, PB_FILE_NAME_SIZE - 1);

  snprintf(slotp->speed_buf, PB_SPEED_SIZE, "---.--B/s");
  snprintf(slotp->time_buf, PB_TIME_SIZE, "--:--:--");

  memset(slotp->time_ring, 0, sizeof(slotp->time_ring));
  memset(slotp->bytes_ring, 0, sizeof(slotp->bytes_ring));

  slotp->cdir = upload ? '>' : '<';

  slotp->total_size = (filesize > 0) ? filesize : 1;
  slotp->xferd_size = 0;
  slotp->start_time = zt_time_now();
  slotp->status = ONGOING;
  slotp->redraw = true; /* redraw on next update */

  if (bar->dont_update == 2)
    bar->dont_update = 0;

  pthread_mutex_unlock(&bar->lock);
}

void zt_progressbar_update(progressbar_t *bar, int slot, size_t nbytes) {
  if (likely(bar)) {
    pthread_mutex_lock(&bar->lock);
    bar->slots[slot].xferd_size += nbytes;
    bar->slots[slot].redraw = true;
    pthread_mutex_unlock(&bar->lock);
  }
}

void zt_progressbar_slot_complete(progressbar_t *bar, int slot) {
  if (bar == NULL)
    return;

  pthread_mutex_lock(&bar->lock);
  if (slot >= 0 && slot < bar->nslots) {
    progressbar_slot *slotp = &bar->slots[slot];
    slotp->status = DONE;
    pb_update_slot(bar, slot);
  }
  pthread_mutex_unlock(&bar->lock);
}

void zt_progressbar_winsize_changed(void) { winsize_changed = true; }
