/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * wordlist.c - Password generation from wordlist
 */

#include "common/defines.h"
#include "common/log.h"
#include "random/systemrand.h"

#include <stdbool.h>
#include <string.h>

#ifdef HAVE_SQLITE3
#include <sqlite3.h>
#endif

static inline bool _validate_separator(char sep) {
  if (sep == 0) /* use the default separator */
    return true;
  if (sep >= 33 /* ! */ && sep <= 47 /* / */)
    return true;
  if (sep >= 58 /* : */ && sep <= 64 /* @ */)
    return true;
  if (sep >= 91 /* [ */ && sep <= 98 /* ` */)
    return true;
  if (sep >= 123 /* { */ && sep <= 126 /* ~ */)
    return true;
  return false;
}

#ifdef HAVE_SQLITE3
#define QUERY_WORDLIST_SIZE "SELECT MAX(id) FROM wordlist;"
#define QUERY_SINGLE_WORD "SELECT word FROM wordlist WHERE id = ?;"

/**
 * Generate a password string using words loaded from a custom wordlist database.
 * The password will consist of a specified number of words, separated by a separator, and
 * optionally including a digit.
 * @param[in] wordlistpath Path to the wordlist database.
 * @param[in] count Number of words to include in the password.
 * @param[in] sep Character to use as a separator between words.
 * @param[in] have_digit Whether to include a digit in the password.
 * @return Pointer to the generated password string, or NULL on failure.
 */
char *auth_passwd_from_wordlist(const char *wordlistpath, unsigned short count, char sep,
                                bool have_digit) {
  sqlite3 *db;
  sqlite3_stmt *stmt;
  int max_idx, digit_idx;
  char *words[count], *passwd_ret = NULL;
  size_t total_size;

  if (wordlistpath == NULL || count < 3 || count > 20)
    return NULL;

  if (!_validate_separator(sep))
    return NULL;

  if (sep == 0)
    sep = '-';

  if (sqlite3_open_v2(wordlistpath, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
    return NULL;

  if (sqlite3_prepare_v2(db, QUERY_WORDLIST_SIZE, -1, &stmt, NULL) != SQLITE_OK)
    goto cleanup;

  if (sqlite3_step(stmt) != SQLITE_ROW)
    goto cleanup;

  max_idx = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);

  for (int i = 0; i < count; ++i) {
    char *text;
    int idx;

    idx = 1 + zt_rand_ranged(max_idx - 1);

    if (sqlite3_prepare_v2(db, QUERY_SINGLE_WORD, -1, &stmt, NULL) != SQLITE_OK)
      goto cleanup;

    if (sqlite3_bind_int(stmt, 1, idx) != SQLITE_OK)
      goto cleanup;

    if (sqlite3_step(stmt) != SQLITE_ROW)
      goto cleanup;

    text = (char *)sqlite3_column_text(stmt, 0);

    if (!text)
      goto cleanup;

    words[i] = zt_strdup(text);

    sqlite3_finalize(stmt);

    if (!words[i])
      goto cleanup;

    total_size += strlen(words[i]) + 1;
  }

  if (have_digit)
    total_size += 1;

  passwd_ret = zt_malloc(total_size);
  if (!passwd_ret)
    goto cleanup;

  digit_idx = have_digit ? zt_rand_ranged(count - 1) : count;

  char *ptr = passwd_ret;
  for (int i = 0; i < count; ++i) {
    size_t len = strlen(words[i]);
    memcpy(ptr, words[i], len);
    ptr += len;

    if (i == digit_idx)
      *ptr++ = '0' + zt_rand_ranged(9);

    *ptr++ = sep;

    zt_free(words[i]);
  }
  *--ptr = '\0';

cleanup:
  if (!passwd_ret)
    log_error(NULL, "Failed to process wordlist (%s)", sqlite3_errmsg(db));
  sqlite3_close(db);
  return passwd_ret;
}
#else
char *auth_passwd_from_wordlist(const char *wordlistpath ATTRIBUTE_UNUSED,
                                unsigned short count ATTRIBUTE_UNUSED,
                                char sep ATTRIBUTE_UNUSED,
                                bool have_digit ATTRIBUTE_UNUSED) {
  return NULL;
}
#endif /* HAVE_SQLITE3 */