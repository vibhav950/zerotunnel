#pragma once

#include <stdlib.h>

// clang-format off
typedef enum {
  EXIT_STATUS_SUCCESS     = EXIT_SUCCESS,
  EXIT_STATUS_GENERIC     = 1,
  EXIT_STATUS_BAD_PARSE   = 2
} exit_status_t;
// clang-format on

void set_exit_status(exit_status_t status);

exit_status_t get_exit_status(void);
