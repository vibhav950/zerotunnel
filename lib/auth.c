#include "auth.h"
#include "common/b64.h"
#include "common/defines.h"
#include "common/hex.h"
#include "common/log.h"
#include "common/sha256.h"
#include "common/ztver.h"
#include "lib/client.h"
#include "ztlib.h"

#include <bsd/readpassphrase.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <systemd/sd-id128.h>
#include <unistd.h>

// "kappaxzerotunnel"
#define ZT_APP_AUTHID128()                                                               \
  SD_ID128_MAKE(6b, 61, 70, 70, 61, 78, 7a, 65, 72, 6f, 74, 75, 6e, 6e, 65, 6c)

extern char *auth_passwd_generate_phonetic(int count, char sep, bool have_digits);

extern char *auth_passwd_generate(int len, char *buf, size_t bufsize, bool ascii);

extern char *auth_passwd_from_wordlist(const char *wordlistpath, unsigned short count,
                                       char sep, bool have_digit);

static char *auth_passwd_prompt(const char *prompt, int flags ATTRIBUTE_UNUSED) {
  int rppflags;
  char buf[MAX_PASSWD_LEN + 1], *ret;

  ASSERT(prompt != NULL);

  rppflags = RPP_ECHO_OFF | RPP_REQUIRE_TTY;
  if (readpassphrase(prompt, buf, sizeof(buf), rppflags) == NULL) {
    log_error(NULL, "readpassphrase(3) failed");
    return NULL;
  }

  ret = zt_strdup(buf);
  memzero(buf, sizeof(buf));
  return ret;
}

static inline ssize_t line_read_hex(const char *line, const char *prefix, char buf[]) {
  ssize_t len = 0;

  while (isspace((unsigned char)*line))
    line++;

  if (prefix && *prefix) {
    size_t prefix_len = strlen(prefix);
    if (strncmp(line, prefix, prefix_len) != 0)
      return -1; // prefix not found
    line += prefix_len;
  }

  while (*line) {
    if (!isxdigit((unsigned char)*line))
      return -1; // invalid hex character
    buf[len++] = *line++;
  }

  buf[len] = '\0';
  return len;
}

static inline ssize_t line_read_decode_b64(const char *line, const char *prefix,
                                           char **buf, ssize_t *enc_len) {
  int len;
  ssize_t elen;

  while (isspace((unsigned char)*line))
    line++;

  if (prefix && *prefix) {
    size_t prefix_len = strlen(prefix);
    if (strncmp(line, prefix, prefix_len) != 0)
      return -1; // prefix not found
    line += prefix_len;
  }

  elen = 0;
  for (const char *linep = line; *linep; linep++, elen++)
    ;
  if (enc_len)
    *enc_len = elen;
  return (ssize_t)zt_b64_decode(line, elen, buf, &len);
}

static inline int line_read_uint(const char *line, uint32_t *val, const char *fmt) {
  return (sscanf(line, fmt, val) != 1) ? -1 : 1;
}

static ssize_t auth_sha256_idhash_hex(const char *id, uint8_t **idhash) {
  ssize_t len;
  uint8_t hashbuf[SHA256_DIGEST_LEN];

  ASSERT(id != NULL);
  ASSERT(idhash != NULL);

  (void)SHA256(id, strlen(id), hashbuf);

  len = zt_hex_encode(hashbuf, SHA256_DIGEST_LEN, idhash);
  return len ? (ssize_t)len : -1;
}

/**
 * Load a password from a password database file.
 *
 * @param[in] passwdfile Path to the password file.
 * @param[in] bundle_id The Id of the bundle to be loaded from the file.
 * @param[in] pwid The Id of the password to be loaded.
 * @param[out] passwd Pointer to the loaded password structure.
 * @return The positive Id of the loaded password or -1 on failure.
 *
 * This function will parse a zerotunnel password file, and try to load a password that
 * satisfies the given parameters. If a password is successfully found, its corresponding
 * entry in the database is marked deleted and the password is overwritten with '0'
 * characters. This means, if this function successfully loads a password, said password
 * is permanently deleted from the database.
 *
 * If a password is found, it is loaded into a `struct passwd` and @p passwd is set to
 * point the same. Once done, the user MUST remember to safely free this memory by calling
 * `zt_auth_passwd_free()`.
 */
passwd_id_t zt_auth_passwd_load(const char *passwdfile, const char *bundle_id,
                                passwd_id_t pwid, struct passwd **passwd) {
  int fd;
  FILE *fp;
  struct flock fl;
  char *buf = NULL, *linep, *pw = NULL;
  uint8_t *idhash;
  uint8_t bufx1[400] = {0};
  size_t bufsize = 0;
  ssize_t nread, pwlen, enc_len;
  passwd_id_t pwid_cmp = -1;
  bool found = false;

  if (passwdfile == NULL || bundle_id == NULL || passwd == NULL || pwid <= 0)
    return -1;

  if ((fd = open(passwdfile, O_RDWR)) < 0) {
    log_error(NULL, "open: Could not open '%s' (%s)", passwdfile, strerror(errno));
    return -1;
  }

  if ((fp = fdopen(fd, "r+")) == NULL) {
    log_error(NULL, "fdopen: Could not open '%s' (%s)", passwdfile, strerror(errno));
    close(fd);
    return -1;
  }

  /** Put a write lock on this file which is held till this function returns */
  fl.l_type = F_WRLCK;
  fl.l_start = 0;
  fl.l_whence = SEEK_SET;
  fl.l_len = 0;
  if (fcntl(fd, F_SETLK, &fl) < 0) {
    log_error(NULL, "fcntl: Failed to acquire x-lock on '%s' (%s)", passwdfile,
              strerror(errno));
    fclose(fp);
    close(fd);
    return -1;
  }

  if (!(*passwd = zt_malloc(sizeof(struct passwd))))
    goto cleanup;

  if (auth_sha256_idhash_hex(bundle_id, &idhash) < 0)
    goto cleanup;

  while ((nread = getline(&buf, &bufsize, fp)) != -1) {
    // enforce a max length on the line size
    // so that we don't read outside the buf
    if (nread > 390)
      continue;
    linep = buf;

    while (isspace(*linep))
      linep++;

    if (!*linep || *linep == '#')
      continue; // skip empty and comment lines

    // read "::<idhash>"
    if (*linep && !found) {
      if (line_read_hex(linep, "::", bufx1) != SHA256_DIGEST_LEN * 2 /* hex chars */) {
        continue;
      }

      if (zt_strcmp(bufx1, idhash) != 0)
        continue;
      found = true;

      linep += SHA256_DIGEST_LEN * 2 + 2;
    }

    // read ":<pwid>:<'x'/' '>:<pw>"
    if (*linep) {
      if (line_read_uint(linep, &pwid_cmp, ":%u:") < 0)
        continue;
      *linep++;

      if ((pwid != -1) && (pwid_cmp != pwid))
        continue;

      linep = strchr(linep, ':');
      if (!linep || *(linep + 1) != ' ' || *(linep + 2) != ':')
        continue; // skip passwords marked used

      // position after the "x" or " " marker
      char *marker = linep + 1;
      linep += 2;

      char *bufx2 = NULL;
      if ((pwlen = line_read_decode_b64(linep, ":", &bufx2, &enc_len)) < 0) {
        zt_free(bufx2);
        continue;
      }

      pw = zt_strmemdup(bufx2, pwlen);

      memzero(bufx2, pwlen);
      zt_free(bufx2);

      if (!pw) {
        pwid_cmp = -1;
        goto cleanup;
      }

      // mark password used
      *marker = 'x';
      linep += 1; // skip the ':', password starts here
      zt_memset(linep, '0', enc_len);

      /* Delete this password from the password file; return failure if
       * this write fails to prevent a password from being used twice */
      if (fseek(fp, -nread, SEEK_CUR) != 0)
        pwid_cmp = -1;
      if (fwrite(buf, 1, nread, fp) != nread)
        pwid_cmp = -1;
      if (fflush(fp) != 0)
        pwid_cmp = -1;

      if (pwid_cmp == -1) {
        memzero(pw, strlen(pw));
        zt_free(pw);
      }

      break; // match found
    }
  }

  if (pw) {
    (*passwd)->id = pwid_cmp;
    (*passwd)->pw = pw;
    (*passwd)->pwlen = strlen(pw);
  } else {
    /* If all passwords are exhausted, we will end up having
     * the final index in pwid_cmp */
    pwid_cmp = -1;
  }

cleanup:
  /** Unlock the file before leaving :-) */
  fl.l_type = F_UNLCK;
  fcntl(fd, F_SETLK, &fl);

  if (pwid_cmp == -1) {
    if (pw)
      zt_free(pw);

    if (*passwd) {
      zt_free(*passwd);
      *passwd = NULL;
    }
  }

  zt_free(idhash);
  free(buf);

  fclose(fp);
  close(fd);

  return pwid_cmp;
}

/**
 * Delete one or more passwords from the password file.
 *
 * @param[in] passwdfile Path to the password file.
 * @param[in] bundle_id  The Id of the bundle to delete passwords for.
 * @param[in] pwid       The Id of the password to delete (or -1 to delete all).
 * @return               -1 on failure.
 *
 * @warning A return value of -1 means certain failure, however a return value of 0
 * indicates a successful parse and not that a password was deleted.
 *
 * This function will parse a zerotunnel password file, and try to delete one or more
 * passwords that match the given parameters. If @p pwid is a positive password Id whose
 * corresponding entry exists in the database for the given @p bundle_id then the password
 * will be marked used and overwritten with '0' characters.
 *
 * A @p pwid value of `-1` will delete all passwords for the given @p bundle_id in the
 * same way described above.
 */
int zt_auth_passwd_delete(const char *passwdfile, const char *bundle_id,
                          passwd_id_t pwid) {
  int ret = -1;
  int fd;
  FILE *fp;
  struct flock fl;
  char *buf = NULL, *linep, *linep_save;
  uint8_t *idhash;
  uint8_t bufx1[400] = {0};
  size_t bufsize = 0;
  ssize_t nread;
  passwd_id_t pwid_cmp;
  bool found = false;

  if (passwdfile == NULL || bundle_id == NULL || pwid == 0)
    return -1;

  if ((fd = open(passwdfile, O_RDWR)) < 0) {
    log_error(NULL, "open: Could not open '%s' (%s)", passwdfile, strerror(errno));
    return -1;
  }

  if ((fp = fdopen(fd, "r+")) == NULL) {
    log_error(NULL, "fdopen: Could not open '%s' (%s)", passwdfile, strerror(errno));
    close(fd);
    return -1;
  }

  /** Put a write lock on this file which is held till this function returns */
  fl.l_type = F_WRLCK;
  fl.l_start = 0;
  fl.l_whence = SEEK_SET;
  fl.l_len = 0;
  if (fcntl(fd, F_SETLK, &fl) < 0) {
    log_error(NULL, "fcntl: Failed to acquire x-lock on '%s' (%s)", passwdfile,
              strerror(errno));
    fclose(fp);
    close(fd);
    return -1;
  }

  if (auth_sha256_idhash_hex(bundle_id, &idhash) < 0)
    goto cleanup;

  while ((nread = getline(&buf, &bufsize, fp)) != -1) {
    if (nread > 390)
      continue;
    linep = buf;

    while (isspace(*linep))
      linep++;

    if (!*linep || *linep == '#')
      continue; // skip empty and comment lines

    // read "::<idhash>"
    if (*linep) {
      if (line_read_hex(linep, "::", bufx1) == SHA256_DIGEST_LEN * 2 /* hex chars */) {
        // Don't delete passwords for other peers
        if (zt_strcmp(bufx1, idhash) != 0) {
          found = false;
          continue;
        }
        linep += SHA256_DIGEST_LEN * 2 + 2;
        found = true;
      }
    }

    // read ":<pwid>:<'x'/' '>:<pw>" and delete the password
    if (*linep) {
      if (line_read_uint(linep, &pwid_cmp, ":%u:") < 0)
        continue;
      *linep++;

      // Delete all passwords for the peer if pwid is -1
      if (!found || (pwid != -1 && pwid_cmp != pwid))
        continue;

      linep = strchr(linep, ':');
      if (!linep || *(linep + 2) != ':')
        continue;

      // mark password used
      *(linep + 1) = 'x';
      // position after the "x" or " " marker
      linep += 2;

      char *bufx2 = NULL;
      ssize_t pwlen, enc_len;
      if ((pwlen = line_read_decode_b64(linep, ":", &bufx2, &enc_len)) < 0) {
        zt_free(bufx2);
        continue;
      }

      linep += 1; // skip the ':', password starts here
      zt_memset(linep, '0', enc_len);

      fseek(fp, -(nread), SEEK_CUR);
      fwrite(buf, 1, nread, fp);
      fflush(fp);
      memzero(bufx2, pwlen);
      zt_free(bufx2);
    }
  }
  ret = 0;

cleanup:
  /** Unlock the file before leaving :-) */
  fl.l_type = F_UNLCK;
  fcntl(fd, F_SETLK, &fl);
  zt_free(idhash);
  free(buf);
  fclose(fp);
  close(fd);
  return ret;
}

/**
 * Generate a password string.
 *
 * @param[in] wordlistfile Path to a custom SQLite3 wordlist database file. If NULL, the
 * default PGP wordlist will be used.
 * @param[in] count Number of words (if using phonetic) or length in characters of the
 * desired password.
 * @param[in] phonetic If true, generate a phonetic password.
 * @return A pointer to the newly created password structure, or NULL on failure.
 *
 * - If @p wordlistfile is not NULL and @p phonetic is true, this function returns a
 *   password made up of @p count words chosen randomly from the wordlist. The
 *   wordlist DB must be an SQLite3 database file with the expected standard schema.
 * - If @p wordlistfile is NULL and @p phonetic is true, this function returns a
 *   password made up of @p count words chosen from the PGP wordlist.
 * - If @p phonetic is false, this function returns a password made up of @p count
 *   random ASCII characters.
 *
 * The returned password struct must be safely freed after use by calling
 * `zt_auth_passwd_free()`.
 */
struct passwd *zt_auth_passwd_single_new(const char *wordlistfile, unsigned short count,
                                         bool phonetic) {
  char *pw;
  struct passwd *passwd;

  if (phonetic && (count < 3 || count > 20))
    return NULL;
  else if (count < 12 || count > 256)
    return NULL;

  if (phonetic) {
    if (wordlistfile)
      pw = auth_passwd_from_wordlist(wordlistfile, count, 0, true);
    else
      pw = auth_passwd_generate_phonetic(count, 0, true);
  } else {
    pw = auth_passwd_generate(count, NULL, 0, true);
  }
  if (!pw)
    return NULL;

  passwd = zt_malloc(sizeof(struct passwd));
  if (!passwd) {
    zt_free(pw);
    return NULL;
  }

  passwd->id = 0;
  passwd->pw = pw;
  passwd->pwlen = count;

  return passwd;
}

/**
 * Generate a new password for the current session.
 *
 * @param[in] passwdfile Path to the password DB file.
 * @param[in] wordlistfile Path to the wordlist DB file.
 * @param[in] auth_type Authentication type.
 * @param[in] bundle_id Bundle Id.
 * @param[in] n_words Number of words.
 * @param[out] passwd Pointer to a pointer to the resulting password structure.
 * @return
 *  - A positive password Id if the password is loaded from a zerotunnel password file.
 *  - 0 upon successful generation of a KAPPA0/2 password.
 *  - -1 on error.
 *
 * This function is intended to be called by the handshake initiator.
 *
 * The used parameter set is determined by the value of @p auth_type
 * - If @p auth_type is KAPPA0, the user is prompted for the pre-shared password from the
 *   tty. In this case @p passwdfile, @p bundle_id, and @p n_words are ignored.
 *
 * - If @p auth_type is KAPPA1, a password is loaded from the zerotunnel password file.
 *   In this case @p passwdfile and @p bundle_id must be provided but @p n_words is
 *   ignored.
 *
 * - If @p auth_type is KAPPA2, a one-time phonetic password will be generated.
 *   If @p wordlistfile is not NULL, the words will be chosen from the given SQLite3
 *   password DB file which must follow the expected schema. Otherwise, the words will be
 *   chosen from the default PGP wordlist. The @p n_words parameter determines the number
 *   of words to generate. In this case @p passwdfile and @p bundle_id are ignored.
 *
 * This way of conditionally choosing required parameters is probably an anti-pattern, but
 * these are supposed to be passed as config variables and hence the options parser must
 * have taken care of them.
 */
passwd_id_t zt_auth_passwd_new(const char *passwdfile, const char *wordlistfile,
                               auth_type_t auth_type, const char *bundle_id, int n_words,
                               struct passwd **passwd) {
  char *pw;

  if ((auth_type == KAPPA_AUTHTYPE_1) && (!passwdfile || !bundle_id))
    return -1;

  if (auth_type == KAPPA_AUTHTYPE_1) {
    int id = zt_auth_passwd_load(passwdfile, bundle_id, -1, passwd);
    if (id < 0) {
      log_error(NULL, "Found no matching entries (bundleId=%s, pwId=%d)", bundle_id, id);
      return -1;
    }

    return id;
  }

  *passwd = zt_malloc(sizeof(struct passwd));
  if (!*passwd)
    return -1;

  if (auth_type == KAPPA_AUTHTYPE_0) {
    pw = auth_passwd_prompt("\nEnter password: ", 0);
  } else if (auth_type == KAPPA_AUTHTYPE_2) {
    if (wordlistfile)
      pw = auth_passwd_from_wordlist(wordlistfile, n_words, 0, true);
    else
      pw = auth_passwd_generate_phonetic(n_words, 0, true);
  }

  if (!pw)
    goto err;

  (*passwd)->id = 0;
  (*passwd)->pw = pw;
  (*passwd)->pwlen = strlen(pw);

  return 0;

err:
  zt_free(*passwd);
  *passwd = NULL;
  return -1;
}

/**
 * Get the session password.
 *
 * @param[in] passwdfile Path to the password DB file.
 * @param[in] auth_type Authentication type.
 * @param[in] bundle_id Bundle Id.
 * @param[in] pwid Password Id.
 * @param[out] passwd Pointer to a pointer to the resulting password structure.
 * @return
 *  - A positive password Id if the password is loaded from a zerotunnel password file.
 *  - 0 upon successful retrieval of the password.
 *  - -1 on error.
 *
 * This function is intended to be called by the handshake responder.
 *
 * The usable set of parameters is determined by the value of @p auth_type
 * - If @p auth_type is KAPPA0, the user is prompted for the pre-shared password from the
 *   tty. In this case @p passwdfile, @p bundle_id, and @p pwid are ignored.
 *
 * - If @p auth_type is KAPPA1, a password is loaded from the zerotunnel password file.
 *   In this case @p passwdfile, @p bundle_id, and @p pwid must be provided. If a password
 *   with the given @p pwid is not found, the function fails.
 *
 * - If @p auth_type is KAPPA2, the user is prompted for the one-time password generated
 *   by the initiator. In this case @p passwdfile, @p bundle_id, and @p pwid are ignored.
 */
passwd_id_t zt_auth_passwd_get(const char *passwdfile, auth_type_t auth_type,
                               const char *bundle_id, passwd_id_t pwid,
                               struct passwd **passwd) {
  if (auth_type == KAPPA_AUTHTYPE_1 && (!passwdfile || !bundle_id))
    return -1;

  if (auth_type == KAPPA_AUTHTYPE_0 || auth_type == KAPPA_AUTHTYPE_2) {
    char *pw;

    ASSERT(pwid == 0);

    *passwd = zt_malloc(sizeof(struct passwd));
    if (!*passwd)
      return -1;

    pw = auth_passwd_prompt("\nEnter password: ", 0);
    if (!pw) {
      zt_free(*passwd);
      return -1;
    }

    (*passwd)->id = 0;
    (*passwd)->pw = pw;
    (*passwd)->pwlen = strlen(pw);

    return 0;
  } else {
    if (zt_auth_passwd_load(passwdfile, bundle_id, pwid, passwd) < 0) {
      log_error(NULL, "Found no matching entries (bundleId=%s, pwId=%d)", bundle_id,
                pwid);
      return -1;
    }

    return pwid;
  }
}

/**
 * Create a new password database file.
 *
 * @param[in] fd An open file descriptor for the password file.
 * @param[in] bundle_id Bundle Id for the password bundle.
 * @param[in] password_len Length of the passwords in the bundle.
 * @param[in] n_passwords Number of passwords in the bundle.
 * @return 0 on success, -1 on failure.
 *
 * The caller must ensure that the @p fd is opened in writeable mode with adequately
 * restrictive permissions.
 */
int zt_auth_passwd_db_new(int fd, const char *bundle_id, unsigned short password_len,
                          unsigned short n_passwords) {
  int ret = 0;
  FILE *fp;
  char buf[MAX_PASSWD_LEN + 1];
  char *passwd_b64 = NULL;
  uint8_t idhash[SHA256_DIGEST_LEN], *idhash_hex = NULL;
  size_t idhash_hex_len;
  int passwd_b64_len;

  if (fd < 3 || bundle_id == NULL)
    return -1;

  if (password_len > MAX_PASSWD_LEN || n_passwords > MAX_BUNDLE_SIZE)
    return -1;

  if ((fp = fdopen(fd, "w")) == NULL) {
    log_error(NULL, "fdopen: Could not open fd=%d (%s)", fd, strerror(errno));
    return -1;
  }

  (void)SHA256(bundle_id, strlen(bundle_id), idhash);

  idhash_hex_len = zt_hex_encode(idhash, SHA256_DIGEST_LEN, &idhash_hex);
  if (idhash_hex_len == 0) {
    ret = -1;
    goto cleanup;
  }

  fprintf(fp, "# zerotunnel v%s\r\n", ZT_VERSION_STRING);
  fprintf(fp, "# Auto-generated password bundle\r\n");
  fprintf(fp, "::%s%c\r\n", idhash_hex, '\0');

  memzero(idhash_hex, idhash_hex_len);
  zt_free(idhash_hex);

  for (int pwidx = 1; pwidx <= n_passwords; ++pwidx) {
    if (auth_passwd_generate(password_len, buf, sizeof(buf), false) == NULL) {
      ret = -1;
      goto cleanup;
    }

    if (zt_b64_encode(buf, password_len, &passwd_b64, &passwd_b64_len) == -1) {
      ret = -1;
      goto cleanup;
    }

    fprintf(fp, ":%u: :%s%c\r\n", pwidx, passwd_b64, '\0');

    memzero(passwd_b64, passwd_b64_len);
    zt_free(passwd_b64);
  }
  memzero(buf, sizeof(buf));

cleanup:
  memzero(idhash, SHA256_DIGEST_LEN);
  fclose(fp);
  if (ret < 0)
    fzero(fd);
  return ret;
}

/**
 * Safely free allocated passwords.
 *
 * Example usage:
 *  zt_auth_passwd_free(pass1, NULL);
 *  zt_auth_passwd_free(pass1, pass2, NULL);
 */
void zt_auth_passwd_free(struct passwd *pass, ...) {
  va_list args;

  va_start(args, pass);

  while (pass != NULL) {
    if (pass->pw != NULL) {
      memzero(pass->pw, pass->pwlen);
      zt_free(pass->pw);
    }
    memzero(pass, sizeof(struct passwd));
    zt_free(pass);
    pass = va_arg(args, struct passwd *);
  }
  va_end(args);
}

/**
 * Places a unique identifier in \p authid which can be used to uniquely
 * identify this machine for a zerotunnel session.
 * This value remains persistent across boots.
 *
 * Returns 0 on success, -1 on failure.
 *
 * Note: the caller MUST explicitly check for a 0 return value to make sure
 * garbage value is not used as the authid.
 *
 * - This authenticator can be securely sent over an untrusted network in
 *   plaintext; and MUST BE sent as part of the first message to a peer (i.e.,
 *   in the first TCP message from the initiator or the first TCP response from
 *   the responder).
 * - For KAPPA verification, this the initiator and responder authid are used
 *   to derive the `VERIFICATION_MSG`.
 */
int zt_get_hostid(struct authid *authid) {
  sd_id128_t base, ret;

  if (unlikely(!authid))
    return -1;

  base = ZT_APP_AUTHID128();

  if (sd_id128_get_machine_app_specific(base, &ret) != 0) {
    log_error(NULL, "Failed to get system ID");
    return -1;
  }

  memcpy((void *)&authid->bytes[0], (void *)&ret.bytes[0], AUTHID_BYTES_LEN);
  return 0;
}
