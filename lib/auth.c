#include "auth.h"
#include "common/b64.h"
#include "common/defines.h"
#include "common/hex.h"
#include "crypto/sha256.h"
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
#define ZT_APP_AUTHID128()                                                     \
  SD_ID128_MAKE(6b, 61, 70, 70, 61, 78, 7a, 65, 72, 6f, 74, 75, 6e, 6e, 65, 6c)

#define ZT_NULL_PEERID_STR "zerotunnel-null-peerid"

extern char *auth_passwd_generate_phonetic(int count, char sep,
                                           bool have_digits);

extern int auth_passwd_generate(char *passwd, int len);

static char *auth_passwd_prompt(const char *prompt,
                                int flags ATTRIBUTE_UNUSED) {
  int rppflags;
  char buf[MAX_PASSWD_LEN + 1], *ret;

  ASSERT(prompt != NULL);

  rppflags = RPP_ECHO_OFF | RPP_REQUIRE_TTY;
  if (readpassphrase(prompt, buf, sizeof(buf), rppflags) == NULL) {
    PRINTERROR("readpassphrase(3) failed");
    return NULL;
  }

  ret = zt_strdup(buf);
  memzero(buf, sizeof(buf));
  return ret;
}

static inline ssize_t line_read_hex(const char *line, const char *prefix,
                                    char buf[]) {
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

static inline int line_read_uint(const char *line, uint32_t *val,
                                 const char *fmt) {
  return (sscanf(line, fmt, val) != 1) ? -1 : 1;
}

static ssize_t auth_sha256_idhash_hex(const char *peer_id, uint8_t **idhash) {
  ssize_t len;
  uint8_t hashbuf[SHA256_DIGEST_LEN];

  ASSERT(peer_id != NULL);
  ASSERT(idhash != NULL);

  (void)SHA256(peer_id, strlen(peer_id), hashbuf);

  len = zt_hex_encode(hashbuf, SHA256_DIGEST_LEN, idhash);
  return len ? (ssize_t)len : -1;
}

passwd_id_t zt_auth_passwd_load(const char *passwddb_file, const char *peer_id,
                                passwd_id_t pwid, char **passwd) {
  int fd;
  FILE *fp;
  struct flock fl;
  char *buf = NULL, *linep;
  uint8_t *idhash;
  uint8_t bufx1[400] = {0};
  size_t bufsize = 0;
  ssize_t nread, pwlen;
  passwd_id_t pwid_cmp;
  bool found = false;

  if (passwddb_file == NULL || peer_id == NULL)
    return -1;

  if ((fd = open(passwddb_file, O_RDWR)) < 0) {
    PRINTERROR("open: could not open %s (%s)", passwddb_file, strerror(errno));
    return -1;
  }

  if ((fp = fdopen(fd, "r+")) == NULL) {
    PRINTERROR("fdopen: could not open %s (%s)", passwddb_file,
               strerror(errno));
    close(fd);
    return -1;
  }

  /** Put a write lock on this file which is held till this function returns */
  fl.l_type = F_WRLCK;
  fl.l_start = 0;
  fl.l_whence = SEEK_SET;
  fl.l_len = 0;
  if (fcntl(fd, F_SETLK, &fl) < 0) {
    PRINTERROR("fcntl: failed to acquire x-lock on %s (%s)", passwddb_file,
               strerror(errno));
    fclose(fp);
    close(fd);
    return -1;
  }

  if (auth_sha256_idhash_hex(peer_id, &idhash) < 0)
    goto cleanup;

  *passwd = NULL;
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

    // strip trailing newline characters
    char *end = buf + nread - 1;
    while (end > buf && (*end == '\n' || *end == '\r'))
      *end-- = '\0';

    // read "::<idhash>"
    if (*linep && !found) {
      if (line_read_hex(linep, "::", bufx1) !=
          SHA256_DIGEST_LEN * 2 /* hex chars */) {
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
      linep += 2;

      if (!(linep = strchr(linep, ':')))
        continue;

      char *bufx2;
      if ((pwlen = line_read_decode_b64(linep, ":", &bufx2, NULL)) < 0) {
        free(bufx2);
        continue;
      }

      *passwd = zt_strmemdup(bufx2, pwlen);
      memzero(bufx2, pwlen);
      free(bufx2);
      break;
    }
  }

cleanup:
  /** Unlock the file before leaving :-) */
  fl.l_type = F_UNLCK;
  fcntl(fd, F_SETLK, &fl);

  zt_free(idhash);
  free(buf);
  fclose(fp);
  close(fd);
  return (*passwd) ? pwid_cmp : -1;
}

int zt_auth_passwd_delete(const char *passwddb_file, const char *peer_id,
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

  if (passwddb_file == NULL || peer_id == NULL)
    return -1;

  if ((fd = open(passwddb_file, O_RDWR)) < 0) {
    PRINTERROR("open: could not open %s (%s)", passwddb_file, strerror(errno));
    return -1;
  }

  if ((fp = fdopen(fd, "r+")) == NULL) {
    PRINTERROR("fdopen: could not open %s (%s)", passwddb_file,
               strerror(errno));
    close(fd);
    return -1;
  }

  /** Put a write lock on this file which is held till this function returns */
  fl.l_type = F_WRLCK;
  fl.l_start = 0;
  fl.l_whence = SEEK_SET;
  fl.l_len = 0;
  if (fcntl(fd, F_SETLK, &fl) < 0) {
    PRINTERROR("fcntl: failed to acquire x-lock on %s (%s)", passwddb_file,
               strerror(errno));
    fclose(fp);
    close(fd);
    return -1;
  }

  if (auth_sha256_idhash_hex(peer_id, &idhash) < 0)
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
      if (line_read_hex(linep, "::", bufx1) ==
          SHA256_DIGEST_LEN * 2 /* hex chars */) {
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

      char *marker_pos = strchr(linep, ':');
      if (!marker_pos || *(marker_pos + 2) != ':')
        continue;
      marker_pos++;

      // position after the "x" or " " marker
      char *pw_start = strchr(marker_pos, ':');
      if (!pw_start)
        continue;

      char *bufx2;
      ssize_t pwlen, enc_len;
      if ((pwlen = line_read_decode_b64(pw_start, ":", &bufx2, &enc_len)) < 0) {
        zt_free(bufx2);
        continue;
      }

      *marker_pos = 'x';
      pw_start++;
      memset(pw_start, '0', enc_len);

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

struct passwd *zt_auth_passwd_new(const char *passwddb_file,
                                  auth_type_t auth_type, const char *peer_id) {
  int rv;
  char *pw;
  passwd_id_t id = -1;
  struct passwd *passwd;

  if (auth_type == KAPPA_AUTHTYPE_1 && passwddb_file == NULL)
    return NULL;

  if ((peer_id == NULL) && (auth_type == KAPPA_AUTHTYPE_1))
    peer_id = ZT_NULL_PEERID_STR;

  if (!(passwd = zt_malloc(sizeof(struct passwd)))) {
    PRINTERROR("out of memory");
    return NULL;
  }

  switch (auth_type) {
  case KAPPA_AUTHTYPE_0:
    if (!(pw = auth_passwd_prompt("Enter password: ", 0)))
      goto err;
    break;
  case KAPPA_AUTHTYPE_1:
    if ((id = zt_auth_passwd_load(passwddb_file, peer_id, id, &pw)) < 0) {
      PRINTERROR("Found no matching password entries (peer_id=%s, pwid=%d)",
                 peer_id, id);
      goto err;
    }
    break;
  case KAPPA_AUTHTYPE_2:
    // TODO: this must be set by config
    if (!(pw = auth_passwd_generate_phonetic(6, 0, 1)))
      goto err;
    break;
  default:
    PRINTERROR("unknown auth type %d", auth_type);
    goto err;
  }
  passwd->id = id;
  passwd->pw = pw;
  passwd->pwlen = strlen(pw);
  return passwd;

err:
  zt_free(passwd);
  return NULL;
}

struct passwd *zt_auth_passwd_get(const char *passwddb_file,
                                  auth_type_t auth_type, const char *peer_id,
                                  passwd_id_t pwid) {
  char *pw;
  struct passwd *passwd;

  if (passwddb_file == NULL)
    return NULL;

  if (peer_id == NULL)
    peer_id = ZT_NULL_PEERID_STR;

  if (!(passwd = zt_malloc(sizeof(struct passwd)))) {
    PRINTERROR("out of memory");
    return NULL;
  }

  switch (auth_type) {
  /* One-time use passwords */
  case KAPPA_AUTHTYPE_0:
  case KAPPA_AUTHTYPE_2:
    if (!(pw = auth_passwd_prompt("Enter password: ", 0)))
      goto err;
    break;
  case KAPPA_AUTHTYPE_1:
    if (zt_auth_passwd_load(passwddb_file, peer_id, pwid, &pw) < 0) {
      PRINTERROR("found no matching entries (peer_id=%s, pwid=%d)", peer_id,
                 pwid);
      goto err;
    }
    break;
  default:
    PRINTERROR("unknown auth type %d", auth_type);
    goto err;
  }
  passwd->id = pwid;
  passwd->pw = pw;
  passwd->pwlen = strlen(pw);
  return passwd;

err:
  zt_free(passwd);
  return NULL;
}

int zt_auth_passwddb_new(const char *passwddb_file, const char *peer_id,
                         int n_passwords) {
  int ret = 0;
  FILE *fp;
  char buf[32 + 1],
      *passwd_b64 = NULL; // TODO: some kind of macro/config for the length
  uint8_t idhash[SHA256_DIGEST_LEN], *idhash_hex = NULL;
  size_t idhash_hex_len;
  int passwd_b64_len;

  if (passwddb_file == NULL || peer_id == NULL)
    return -1;

  if (!n_passwords || n_passwords > 256) {
    PRINTERROR("requested password bundle of invalid size", n_passwords);
    return -1;
  }

  if ((fp = fopen(passwddb_file, "w")) == NULL) {
    PRINTERROR("fopen: could not open %s (%s)", passwddb_file, strerror(errno));
    return -1;
  }

  (void)SHA256(peer_id, strlen(peer_id), idhash);

  if ((idhash_hex_len =
           zt_hex_encode(idhash, SHA256_DIGEST_LEN, &idhash_hex)) == 0) {
    PRINTERROR("out of memory");
    ret = -1;
    goto cleanup;
  }

  // fprintf(fp, "zerotunnel v%s\r\n", ZEROTUNNEL_VERSION_STRING);
  fprintf(fp, "# zerotunnel v1.0.1\r\n");
  fprintf(fp, "# Auto-generated password bundle\r\n", peer_id);
  fprintf(fp, "::%s%c\r\n", idhash_hex, '\0');

  memzero(idhash_hex, idhash_hex_len);
  zt_free(idhash_hex);

  for (int i = 0; i < n_passwords; i++) {
    if (auth_passwd_generate(buf, 33) == -1) { // TODO: hardcoded length
      ret = -1;
      goto cleanup;
    }

    if (zt_b64_encode(buf, 32, &passwd_b64, &passwd_b64_len) == -1) {
      PRINTERROR("out of memory");
      ret = -1;
      goto cleanup;
    }

    fprintf(fp, ":%u: :%s%c\r\n", i + 1, passwd_b64, '\0');

    memzero(passwd_b64, passwd_b64_len);
    zt_free(passwd_b64);
  }
  memzero(buf, sizeof(buf));

cleanup:
  memzero(idhash, SHA256_DIGEST_LEN);
  fclose(fp);
  if (ret < 0)
    remove(passwddb_file);
  return ret;
}

/** Safely free passwords */
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
 * plaintext; and MUST BE sent as part of the first message to a peer (i.e., in
 * the first TCP message from the initiator or the first TCP response from the
 * responder).
 * - For KAPPA verification, this the initiator and responder authid are used to
 * derive the `VERIFICATION_MSG`.
 */
int zt_get_hostid(struct authid *authid) {
  sd_id128_t base, ret;

  if (unlikely(!authid))
    return -1;

  base = ZT_APP_AUTHID128();

  if (sd_id128_get_machine_app_specific(base, &ret) != 0) {
    PRINTERROR("failed to get system ID");
    return -1;
  }

  zt_memcpy((void *)&authid->bytes[0], (void *)&ret.bytes[0], AUTHID_LEN_BYTES);
  return 0;
}

// cd lib
// gcc -I../ -lbsd -lsystemd auth.c passgen.c ../random/systemrand.c
// ../common/memzero.c \
// ../common/mem.c ../common/x86_cpuid.c ../common/log.c ../random/rdrand.c \
// ../common/hex.c ../common/b64.c ../crypto/sha256.c ../crypto/sha256_alg.c \
// ../crypto/sha256_x86.c

#include <stdio.h>

int main() {
  const char *passwddb_file = "passwddb.txt";
  const char *peer_id = "peer1";
  char *pw;

  // ASSERT(zt_auth_passwddb_new(passwddb_file, peer_id, 10) == 0);

  for (int i = 1; i <= 10; ++i) {
    ASSERT(zt_auth_passwd_load(passwddb_file, peer_id, i, &pw) > 0);
    printf("Password: %s\n", pw);
    zt_free(pw);
  }

  // ASSERT(zt_auth_passwd_delete(passwddb_file, peer_id, -1) == 0);

  return 0;
}
