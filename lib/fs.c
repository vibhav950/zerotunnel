/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * fs.c - Filesystem iteration utilities
 *
 * To-do:
 * - Recursive directory iteration
 */

#include "dir.h"
#include "common/sha256.h"
#include "common/vec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include <sys/stat.h>

struct _fs_iter_st {
  char *root;        /* root directory path */
  uint32_t mode;     /* root directory permission flags */
  zt_vec_t *entries; /* vector of `fs_entry_t` */
  uint32_t nents;    /* number of entries in this iterator */
  uint32_t idx;      /* current iteration index */
};

static inline int ATTRIBUTE_ALWAYS_INLINE _is_sep(char c) {
#if defined(_WIN32)
  return c == '/' || c == '\\';
#else
  return c == '/';
#endif
}

static inline void ATTRIBUTE_ALWAYS_INLINE ATTRIBUTE_NONNULL(1, 3, 4)
    _join_path(char *dst, size_t dstsz, const char *dir, const char *name) {
  size_t dl = strlen(dir);
  int need_sep = dl > 0 && !_is_sep(dir[dl - 1]);
#ifdef _WIN32
  snprintf(dst, dstsz, need_sep ? "%s\\%s" : "%s%s", dir, name);
#else
  snprintf(dst, dstsz, need_sep ? "%s/%s" : "%s%s", dir, name);
#endif
}

static void _entry_destructor(void *ele) {
  fs_entry_t *ent = (fs_entry_t *)ele;
  zt_free(ent->name);
}

/**
 * Synchronously and nonrecursively iterate over all entries under \p dirpath
 * and record the following stats for each regular file into \p ctx:
 *  - name relative to \p dirpath
 *  - disk size in bytes
 *  - filesystem permission flags
 *
 * @note Limits the number of entries to \p max (if not -1),
 * and fails if this value is exhausted before the entire directory is traversed.
 */
static err_t _dir_iterate(const char *dirpath, fs_iter_t *ctx, int max) {
  err_t ret = ERR_SUCCESS;
  char path[4096];
  uv_fs_t scandir_req, st_req;
  uv_dirent_t dent;
  uv_stat_t st;
  int cnt;

  int r = uv_fs_scandir(NULL, &scandir_req, dirpath, 0, NULL); /* sync */
  if (r < 0) {
    ret = ERR_INTERNAL;
    goto out;
  }

  while ((r = uv_fs_scandir_next(&scandir_req, &dent)) == 0 &&
         (max != -1 && ++cnt <= max)) {
    // if (!strcmp(dent.name, ".") || !strcmp(dent.name, ".."))
    // continue;

    /* path = dirname/entry_name */
    _join_path(dirpath, sizeof dirpath, dirpath, dent.name);

    int sr = uv_fs_stat(NULL, &st_req, dirpath, NULL); /* sync */
    if (sr != 0) {
      uv_fs_req_cleanup(&st_req);
      ret = ERR_INTERNAL;
      goto out;
    }

    st = st_req.statbuf;
    /* copy stats to the entries vector */
    if (S_ISREG(st.st_mode)) {
      int idx;
      idx = zt_vec_append_shallowcopy(ctx->entries,
                                      &(fs_entry_t){
                                          .name = zt_strdup(dent.name),
                                          .size = st_req.statbuf.st_size,
                                          .mode = st_req.statbuf.st_mode,
                                      },
                                      sizeof(fs_entry_t));
      if (idx == -1) {
        uv_fs_req_cleanup(&st_req);
        ret = ERR_MEM_FAIL;
        goto out;
      }
    }
    uv_fs_req_cleanup(&st_req);
  }

  if (r != UV_EOF) {
    if (cnt == max)
      ret = ERR_OPERATION_LIMIT_REACHED;
    else
      ret = ERR_INTERNAL;
  } else {
    ctx->nents = zt_vec_size(ctx->entries);
    ctx->root = zt_strdup(dirpath);
  }

out:
  uv_fs_req_cleanup(&scandir_req);
  return ret;
}

static int _fsent_cmp_name_asc(const void *a, const void *b) {
  const fs_entry_t *ea = a, *eb = b;

  return strcmp(ea->name, eb->name);
}

static int _fsent_cmp_name_dsc(const void *a, const void *b) {
  const fs_entry_t *ea = a, *eb = b;

  return strcmp(eb->name, ea->name);
}

static int _fsent_cmp_size_asc(const void *a, const void *b) {
  const fs_entry_t *ea = a, *eb = b;

  if (ea->size == eb->size)
    return 0;
  else
    return ea->size < eb->size ? -1 : 1;
}

static int _fsent_cmp_size_dsc(const void *a, const void *b) {
  const fs_entry_t *ea = a, *eb = b;

  if (ea->size == eb->size)
    return 0;
  else
    return ea->size > eb->size ? -1 : 1;
}

/**
 * \param[in] iter A pointer to an uninitialized `fs_iter_t` object.
 * \param[in] path Full target path.
 * \param[in] order The order in which to return entries.
 * \param[in] limit The max number of entries allowed, or -1 for no limit.
 * \param[in] f_rand A pointer to a cryptographically secure random function to generate
 * stream Ids for each collected entry.
 * \return An `err_t` error code.
 *
 * Initializes a `fs_iter_t` instance which can be used to iterate over multiple
 * filesystem entries in the specified \p order by repeatedly calling `fs_iter_next()`.
 *
 * If \p path is a directory, this creates an iterator of all regular files that are
 * direct children of \p path. If \p path is a regular file, this creates an iterator with
 * a single entry representing that file.
 *
 * Use `fs_iter_destroy()` to release this iterator's resources after use.
 *
 * This function may block for a while since it iterates over all filesystem entries under
 * \p path and copies them to an internal dynamic data structure.
 *
 * If \p limit is exhausted before all entries are read, the function returns
 * `ERR_OPERATION_LIMIT_REACHED`. This could be helpful in memory-constrained environments
 * and ensures that we never use more that `limit * sizeof(fs_entry_t)` bytes plus some
 * additional bytes for bookkeeping info.
 */
err_t fs_iter_new(fs_iter_t *iter, const char *path, fs_iter_order_t order, int limit,
                  secure_random_func_t *f_rand) {
  err_t ret = ERR_SUCCESS;
  fs_iter_t *iter;
  size_t nents;
  int r;
  uv_fs_t st_req;
  zt_vec_cmp_func_t *cmp;

  if (!iter || !path)
    return ERR_NULL_PTR;

  if (limit != -1 && limit <= 0)
    return ERR_BAD_ARGS;

  memset(iter, 0, sizeof(fs_iter_t));

  switch (order) {
  case FS_ITER_ORDER_NAME_ASC:
    cmp = _fsent_cmp_name_asc;
    break;
  case FS_ITER_ORDER_NAME_DSC:
    cmp = _fsent_cmp_name_dsc;
    break;
  case FS_ITER_ORDER_SIZE_ASC:
    cmp = _fsent_cmp_size_asc;
    break;
  case FS_ITER_ORDER_SIZE_DSC:
    cmp = _fsent_cmp_size_dsc;
    break;
  case FS_ITER_ORDER_NONE:
    cmp = NULL;
    break;
  default:
    return ERR_BAD_ARGS;
  }

  iter->entries = zt_vec_new(0 /*default capacity*/, cmp);
  if (!iter->entries)
    return ERR_MEM_FAIL;

  zt_vec_set_destructor(iter->entries, _entry_destructor);

  r = uv_fs_stat(NULL, &st_req, path, NULL); /* sync */
  if (r != 0) {
    uv_fs_req_cleanup(&st_req);
    zt_vec_free(&iter->entries);
    return ERR_INTERNAL;
  }

  if (S_ISDIR(st_req.statbuf.st_mode)) {
    ret = _dir_iterate(path, iter, limit);
  } else if (S_ISREG(st_req.statbuf.st_mode)) {
    /* single file entry */
    int idx;
    uint32_t sid;

    f_rand(PTR8(&sid), sizeof(uint32_t));

    idx = zt_vec_append_shallowcopy(iter->entries,
                                    &(fs_entry_t){.name = zt_strdup(path),
                                                  .size = st_req.statbuf.st_size,
                                                  .mode = st_req.statbuf.st_mode,
                                                  .id = sid},
                                    sizeof(fs_entry_t));
    if (idx == -1) {
      uv_fs_req_cleanup(&st_req);
      zt_vec_free(&iter->entries);
      return ERR_MEM_FAIL;
    }
    iter->nents = 1;
    iter->root = zt_strdup("\0");
  } else {
    ret = ERR_BAD_ARGS;
  }
  uv_fs_req_cleanup(&st_req);

  if (ret)
    zt_vec_free(&iter->entries);

  return ret;
}

/**
 * \param[in] iter A pointer to an initialized `fs_iter_t` object.
 * \param[out] ent A pointer to the output `fs_entry_t` pointer.
 * \return An `err_t` error code.
 *
 * Get the next entry from the iterator \p iter into the \p ent pointer.
 *
 * If there are no more entries to return, `ERR_EOF` is returned.
 */
err_t fs_iter_next(fs_iter_t *iter, fs_entry_t **ent) {
  fs_entry_t *e;

  if (!iter || !ent)
    return ERR_NULL_PTR;

  if (iter->idx >= iter->nents)
    return ERR_EOF;

  e = zt_vec_get(iter->entries, iter->idx);
  if (!e)
    return ERR_INVALID;

  iter->idx++;
  *ent = e;

  return ERR_SUCCESS;
}

/**
 * \param[in] iter A pointer to an initialized `fs_iter_t` object.
 * @return void
 *
 * Free all resources associated with the iterator \p iter without freeing
 * the \p iter object itself.
 */
void fs_iter_destroy(fs_iter_t *iter) {
  if (iter) {
    zt_vec_free(&iter->entries);
    zt_free(iter->root);
    memset(iter, 0, sizeof(fs_iter_t));
  }
}

// clang-format off
/*
  Encoding format for the directory manifest:

  field         | [ checksum ][ dir-mode ][ nents ][ dirname ] [[ size ][ mode ][ fileId ][ relpath ]...]
  size (bytes)  |  <---16--->  <----4--->  <--4-->  <--var-->  [ <--8->  <--4->  <---4-->  <--var-->    ] x nents

  - Strings must be nul-terminated
  - Multi-byte integers are stored in network byte order
*/
// clang-format on

/**
 *
 */
static inline size_t ATTRIBUTE_NONNULL(1) _encoded_len(const fs_iter_t *iter) {
  size_t clen = 0;

  clen += 16 + 4 + 4; // checksum + dir-mode + nents
  clen += strlen(iter->root) + 1 /*nul-byte*/;
  for (int ent = 0; ent < iter->nents; ent++) {
    fs_entry_t *e = zt_vec_get(iter->entries, ent);
    clen += 8 + 4;                       // size + mode
    clen += strlen(e->name) + 1 /*nul*/; // relpath
  }
  return clen;
}

/**
 * Check that the encoded length is safe to parse.
 *
 * @note This only rejects malformed encodings so we don't read out of bounds;
 * the actual content validity is checked during decoding.
 */
static inline int _check_safe_encoding(size_t len) {
  if (len < 16 + 4 + 4 + 1) // checksum + dir-mode + nents + at least 1 byte for dirname
    return -1;
  return 0;
}

/**
 * Encode the iteraator \p iter into the buffer \p buf.
 * \return An `err_t` error code.
 *
 * The buffer \p buf must be at least `_encoded_len(iter)` bytes long.
 *
 * The 16-byte checksum at the start of the encoding is the last 16 bytes
 * of the SHA256 hash computed over the rest of the data.
 */
static err_t ATTRIBUTE_NONNULL(1, 2) _encode_iter(const fs_iter_t *iter, uint8_t *buf) {
  uint8_t *p = buf;
  uint32_t t32;
  uint64_t t64;
  uint8_t tmp[32];

#define _COPY_STR(dst, src)                                                              \
  ({                                                                                     \
    size_t _slen = 0;                                                                    \
    while ((src)[_slen]) {                                                               \
      (dst)[_slen] = (src)[_slen];                                                       \
      _slen++;                                                                           \
    }                                                                                    \
    (dst)[_slen] = '\0';                                                                 \
    (_slen + 1);                                                                         \
  })

  p += 16; /* skip checksum */

  /* copy dir-mode */
  t32 = hton32(iter->mode);
  memcpy(p, PTRV(&t32), sizeof(uint32_t));
  p += sizeof(uint32_t);

  /* copy nents */
  t32 = hton32(iter->nents);
  memcpy(p, PTRV(&t32), sizeof(uint32_t));
  p += sizeof(uint32_t);

  /* copy dirname */
  p += _COPY_STR(p, iter->root);

  for (int ent = 0; ent < iter->nents; ent++) {
    fs_entry_t *e = zt_vec_get(iter->entries, ent);
    if (!e)
      return ERR_BAD_ARGS;

    /* copy entry size */
    t64 = hton64(e->size);
    memcpy(p, PTRV(&t64), sizeof(uint64_t));
    p += sizeof(uint64_t);

    /* copy entry mode */
    t32 = hton32(e->mode);
    memcpy(p, PTRV(&t32), sizeof(uint32_t));
    p += sizeof(uint32_t);

    /* copy fileId */
    t32 = hton32(e->id);
    memcpy(p, PTRV(&t32), sizeof(uint32_t));
    p += sizeof(uint32_t);

    /* copy entry relpath */
    p += _COPY_STR(p, e->name);
  }

  /* compute checksum */
  SHA256(buf + 16, (p - buf) - 16, tmp);
  memcpy(buf, tmp + 16, 16); // copy last 16 bytes into checksum field
  return ERR_SUCCESS;
#undef _COPY_STR
}

/**
 * Safely decode the buffer \p buf of length \p len into the iterator \p iter.
 * \return An `err_t` error code.
 *
 * The iterator \p iter must be uninitialized. This function will initialize the \p iter
 * object and allocate the entries vector and all other dynamic memory fields.
 * This object must be released using `fs_iter_destroy()` after use.
 *
 * An `ERR_INVALID_DATUM` is returned if the checksum or encoding is invalid.
 */
static err_t ATTRIBUTE_NONNULL(1, 2)
    _decode_iter(fs_iter_t *iter, const uint8_t *buf, size_t len) {
  err_t ret;
  uint8_t *p = (uint8_t *)buf;
  uint32_t entcnt;
  uint8_t tmp[32];
  size_t rem, t;
  int r;

  if (!_check_safe_encoding(len))
    return ERR_BAD_ARGS;

  memset(iter, 0, sizeof(fs_iter_t));

  /* verify checksum */
  SHA256(buf + 16, len - 16, tmp);
  if (memcmp(buf, tmp + 16, 16) != 0) // compare last 16 bytes of SHA256 hash
    return ERR_INVALID_DATUM;

  p += 16; /* checksum */
  rem = len - 16;

  /* read dir-mode */
  iter->mode = ntoh32(*(uint32_t *)p);
  p += sizeof(uint32_t);
  rem -= sizeof(uint32_t);

  /* read nents */
  iter->nents = ntoh32(*(uint32_t *)p);
  p += sizeof(uint32_t);
  rem -= sizeof(uint32_t);

  /* read dirname */
  iter->root = zt_strndup((char *)p, rem);
  if (!iter->root) {
    t = strnlen(iter->root, rem) + 1;
    p += t;
    rem -= t;
  } else {
    ret = ERR_MEM_FAIL;
    goto err;
  }

  iter->entries = zt_vec_new(iter->nents, NULL);
  if (!iter->entries) {
    ret = ERR_MEM_FAIL;
    goto err;
  }

  zt_vec_set_destructor(iter->entries, _entry_destructor);

  for (uint32_t ent = 0; ent < iter->nents; ent++) {
    fs_entry_t e;
    char *name;

    if (rem < sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + 1) {
      ret = ERR_INVALID_DATUM;
      goto err;
    }

    /* read entry size */
    e.size = ntoh64(*(uint64_t *)p);
    p += sizeof(uint64_t);
    rem -= sizeof(uint64_t);

    /* read entry mode */
    e.mode = ntoh32(*(uint32_t *)p);
    p += sizeof(uint32_t);
    rem -= sizeof(uint32_t);

    /* read fileId */
    e.id = ntoh32(*(uint32_t *)p);
    p += sizeof(uint32_t);
    rem -= sizeof(uint32_t);

    name = zt_strndup((char *)p, rem);
    if (!name) {
      ret = ERR_MEM_FAIL;
      goto err;
    }

    r = zt_vec_append_shallowcopy(iter->entries,
                                  &(fs_entry_t){
                                      .name = name,
                                      .size = e.size,
                                      .mode = e.mode,
                                  },
                                  sizeof(fs_entry_t));
    if (r == -1) {
      zt_free(name);
      ret = ERR_MEM_FAIL;
      goto err;
    }

    t = strnlen((char *)p, rem) + 1;
    p += t;
    rem -= t;
  }

  return ERR_SUCCESS;

err:
  zt_vec_free(&iter->entries);
  zt_free(iter->root);
  return ret;
}

/**
 * \param[in] iter Pointer to an *initialized* `fs_iter_t` object.
 * \param[out] buf Pointer to the output buffer pointer.
 * \param[out] len Pointer to the output buffer length.
 * \return An `err_t` error code.
 *
 * Export the iterator \p iter into a newly allocated buffer \p buf of length \p len.

 * The buffer \p buf must be freed using `zt_free()` after use.
 */
err_t fs_iter_export(fs_iter_t *iter, uint8_t **buf, size_t *len) {
  uint8_t *p;
  err_t ret;

  if (!iter || !buf || !len)
    return ERR_NULL_PTR;

  *len = _encoded_len(iter);

  if ((p = zt_malloc(*len)) == NULL)
    return ERR_MEM_FAIL;

  ret = _encode_iter(iter, p);
  if (ret != ERR_SUCCESS) {
    zt_free(p);
    return ret;
  }

  *buf = p;

  return ERR_SUCCESS;
}

/**
 * \param[in] iter Pointer to an *uninitialized* `fs_iter_t` object.
 * \param[in] buf Pointer to the input buffer.
 * \param[in] len Length of the input buffer.
 * \return An `err_t` error code.
 *
 * Import the iterator \p iter from the buffer \p buf of length \p len.
 */
err_t fs_iter_import(fs_iter_t *iter, const uint8_t *buf, size_t len) {
  if (!iter || !buf)
    return ERR_NULL_PTR;

  return _decode_iter(iter, buf, len);
}
