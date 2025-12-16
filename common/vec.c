/**
 * zerotunnel - Secure P2P file tunneling project
 * Copyright (C) 2025 zerotunnel contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ==============================================
 *
 * vec.c - vector implementation based on the one from wget2,
 * originally written by Tim Ruehsen.
 * Modified for zerotunnel.
 * Reference: https://gitlab.com/gnuwget/wget2/-/blob/master/libwget/vector.c
 */

#include "vec.h"

#include <stdlib.h>
#include <string.h>

// clang-format off
struct _zt_vec_st {
  void
    **entries;
  int
    idx,
    capacity;
  float
    resize_factor;
  bool
    sorted : 1;
  zt_vec_cmp_func_t
    *cmp;
  zt_vec_iter_func_t
    *destructor;
};
// clang-format on

/**
 * \param[in] capacity The initial capacity of the vector. If 0, the default capacity of
 * `ZT_VEC_DEFAULT_CAPACITY` is used.
 * \param[in] cmp A comparison function for the entries. If NULL, the vector cannot be
 * sorted.
 * \return A pointer to a new `zt_vec_t` instance or NULL on error.
 *
 * Allocate a new `zt_vec_t` instance with the specified initial capacity. This object
 * must be freed after use using `zt_vec_free()`.
 *
 * The resize_factor is set to `ZT_VEC_DEFAULT_RESIZE_FACTOR`. To change it, see
 * `zt_vec_set_resize_factor()`.
 */
zt_vec_t *zt_vec_new(size_t capacity, zt_vec_cmp_func_t *cmp) {
  zt_vec_t *vec;

  vec = zt_calloc(1, sizeof(zt_vec_t));
  if (!vec)
    return NULL;

  capacity = (capacity == 0) ? ZT_VEC_DEFAULT_CAPACITY : capacity;
  vec->entries = zt_calloc(capacity, sizeof(void *));
  if (!vec->entries) {
    zt_free(vec);
    return NULL;
  }

  vec->capacity = capacity;
  vec->resize_factor = ZT_VEC_DEFAULT_RESIZE_FACTOR;
  vec->sorted = (cmp != NULL);
  vec->cmp = cmp;
  vec->destructor = zt_free;

  return vec;
}

static inline bool ATTRIBUTE_ALWAYS_INLINE ATTRIBUTE_NONNULL(1) _vec_full(zt_vec_t *vec) {
  return vec->idx >= vec->capacity;
}

static int ATTRIBUTE_NONNULL(1) _resize_vec(zt_vec_t *vec) {
  int new_capacity = (int)(vec->capacity * vec->resize_factor);

  if (new_capacity <= vec->capacity)
    return -1;

  void **new = zt_realloc(vec->entries, new_capacity * sizeof(void *));
  if (!new)
    return -1;

  vec->entries = new;
  vec->capacity = new_capacity;

  return 0;
}

/**
 * Insert an entry at the specified index.
 *
 * If `replace == 1`, the entry at index `idx` is replaced, otherwise entries
 * at and after `idx` are shifted one position to the right.
 */
static int ATTRIBUTE_NONNULL(2)
    _vec_insert_at(zt_vec_t *vec, const void *entry, int idx, bool replace) {
  if (unlikely(!vec))
    return -1;

  if (unlikely(idx < 0 || idx > vec->idx))
    return -1;

  if (!replace) {
    if (_vec_full(vec) && _resize_vec(vec) < 0)
      return -1;

    memmove(&vec->entries[idx + 1], &vec->entries[idx],
            (vec->idx - idx) * sizeof(void *));
    vec->idx++;
  }

  vec->entries[idx] = (void *)entry;

  /* check if we have disturbed sorted ordering */
  if (vec->cmp) {
    if (vec->idx == 1)
      vec->sorted = true;
    else if (vec->idx > 1 && vec->sorted) {
      if (idx == 0) {
        if (vec->cmp(entry, vec->entries[1]) > 0)
          vec->sorted = false;
      } else if (idx == vec->idx - 1) {
        if (vec->cmp(entry, vec->entries[vec->idx - 2]) < 0)
          vec->sorted = false;
      } else {
        if (vec->cmp(entry, vec->entries[idx - 1]) < 0 ||
            vec->cmp(entry, vec->entries[idx + 1]) > 0)
          vec->sorted = false;
      }
    }
  }

  return idx; /* inserted index */
}

/**
 * \param[in] vec The vector to insert into.
 * \param[in] entry The entry to insert.
 * \param[in] idx The index to insert at.
 * \return The index of the inserted entry or -1 on error.
 *
 * Insert an entry at the specified index.
 *
 * This *doesn't* copy \p entry but transfers its ownership to the vector.
 */
int zt_vec_insert(zt_vec_t *vec, const void *entry, int idx) {
  return _vec_insert_at(vec, entry, idx, false);
}

/**
 * \param[in] vec The vector to insert into.
 * \param[in] entry The entry to insert.
 * \return The index of the inserted entry or -1 on error.
 *
 * Insert an entry into the vector, preserving the sort order. If the vector is not
 * sorted, it will be sorted after insertion. If no comparison function is set, the
 * element is appended at the end.
 *
 * This *doesn't* copy \p entry but transfers its ownership to the vector.
 */
int zt_vec_insert_sorted(zt_vec_t *vec, const void *entry) {
  int l, r, m, cres;

  if (unlikely(!vec))
    return -1;

  if (!vec->cmp)
    return _vec_insert_at(vec, entry, vec->idx, false);

  if (!vec->sorted) {
    int r;
    if ((r = _vec_insert_at(vec, entry, vec->idx, false)) > 0)
      zt_vec_sort(vec);
    return r;
  }

  /* binary search for the correct position */
  l = 0;
  r = vec->idx - 1;
  while (l <= r) {
    m = l + (r - l) / 2;
    cres = vec->cmp(entry, vec->entries[m]);
    if (cres == 0)
      return _vec_insert_at(vec, entry, m, false);
    else
      (void)((cres > 0) ? (l = m + 1) : (r = m - 1));
  }
  if (cres > 0)
    m++;

  return _vec_insert_at(vec, entry, m, false);
}

/**
 * \param[in] vec The vector to append to.
 * \param[in] entry The entry to append.
 * \return The index of the appended entry or -1 on error.
 *
 * Append an entry to the end of the vector. This will *not* preserve sorted ordering.
 *
 * This *doesn't* copy \p entry but transfers its ownership to the vector.
 */
int zt_vec_append(zt_vec_t *vec, const void *entry) {
  return _vec_insert_at(vec, entry, vec->idx, false);
}

/**
 * \param[in] vec The vector to append to.
 * \param[in] entry The entry to copy and append.
 * \param[in] size The size of the entry in bytes.
 * \return The index of the appended entry or -1 on error.
 *
 * Append a shallow copy of the entry to the end of the vector. This will *not* preserve
 * sorted ordering.
 */
int zt_vec_append_shallowcopy(zt_vec_t *vec, const void *entry, size_t size) {
  void *copy;

  if (unlikely(!vec))
    return -1;

  copy = zt_memdup(entry, size);
  if (!copy)
    return -1;

  return _vec_insert_at(vec, copy, vec->idx, false);
}

/**
 * \param[in] vec The vector to append to.
 * \param[in] fmt The format string.
 * \param[in] args The variable argument list.
 * \return The index of the appended string or -1 on error.
 *
 * Append a printf-like formatted string to the end of the vector.
 */
int zt_vec_append_vprintf(zt_vec_t *vec, const char *fmt, va_list args) {
  char *str;

  if (unlikely(!vec || !fmt))
    return -1;

  str = zt_vstrdup(fmt, args);
  if (!str)
    return -1;

  return _vec_insert_at(vec, PTRV(str), vec->idx, false);
}

/**
 * \param[in] vec The vector to append to.
 * \param[in] fmt The format string.
 * \param[in] ... The arguments for the format string.
 * \return The index of the appended string or -1 on error.
 *
 * Append a printf-like formatted string to the end of the vector.
 */
int zt_vec_append_printf(zt_vec_t *vec, const char *fmt, ...) {
  va_list args;
  char *str;

  if (unlikely(!vec || !fmt))
    return -1;

  va_start(args, fmt);
  str = zt_vstrdup(fmt, args);
  va_end(args);

  if (!str)
    return -1;

  return _vec_insert_at(vec, PTRV(str), vec->idx, false);
}

/**
 * \param[in] vec The vector to modify.
 * \param[in] entry The new entry.
 * \param[in] idx The index of the entry to replace.
 * \return The index of the replaced entry or -1 on error.
 *
 * Replace the entry at \p idx with \p entry, calling the destructor (if any)
 * on the old entry.
 *
 * \p entry is *not* copied but its ownership is transferred to the vector.
 */
int zt_vec_replace(zt_vec_t *vec, const void *entry, int idx) {
  if (unlikely(!vec || idx < 0 || idx >= vec->idx))
    return -1;

  if (vec->destructor)
    vec->destructor(vec->entries[idx]);

  return _vec_insert_at(vec, entry, idx, true /*replace*/);
}

/**
 * Remove the entry at index `idx`, calling the destructor (if any)
 * if `free_entry` is `true`.
 * Returns the removed entry if `free_entry` is `false`, `NULL` otherwise.
 */
static void *_vec_remove_from(zt_vec_t *vec, int idx, bool free_entry) {
  void *old = NULL;

  if (unlikely(!vec || idx < 0 || idx >= vec->idx))
    return NULL;

  if (free_entry && vec->destructor)
    vec->destructor(vec->entries[idx]);
  else
    old = vec->entries[idx];

  memmove(&vec->entries[idx], &vec->entries[idx + 1],
          (vec->idx - idx - 1) * sizeof(void *));
  vec->idx--;

  return old;
}

/**
 * \param[in] vec The vector to modify.
 * \param[in] idx The index of the entry to remove.
 *
 * Remove the entry at \p index ,freeing it using the destructor (if any).
 */
void zt_vec_remove(zt_vec_t *vec, int idx) {
  _vec_remove_from(vec, idx, true /*free_entry*/);
}

/**
 * \param[in] vec The vector to modify.
 * \param[in] idx The index of the entry to remove.
 * \return The removed entry or NULL on error.
 *
 * Remove the entry at \p index without freeing it.
 */
void *zt_vec_remove_nofree(zt_vec_t *vec, int idx) {
  return _vec_remove_from(vec, idx, false /*free_entry*/);
}

/**
 * \param[in] vec The vector to modify.
 * \param[in] old_idx The current index of the entry.
 * \param[in] new_idx The new index for the entry.
 * \return The new index of the entry or -1 on error.
 *
 * Move an entry from \p old_idx to \p new_idx ,shifting other entries
 * as necessary.
 */
int zt_vec_move(zt_vec_t *vec, int old_idx, int new_idx) {
  void *tmp;

  if (unlikely(!vec || old_idx < 0 || old_idx >= vec->idx || new_idx < 0 ||
               new_idx >= vec->idx))
    return -1;

  if (vec->sorted && vec->cmp && vec->cmp(vec->entries[old_idx], vec->entries[new_idx]))
    vec->sorted = false;

  tmp = vec->entries[old_idx];
  if (old_idx < new_idx)
    memmove(&vec->entries[old_idx], &vec->entries[old_idx + 1],
            (new_idx - old_idx) * sizeof(void *));
  else
    memmove(&vec->entries[new_idx + 1], &vec->entries[new_idx],
            (old_idx - new_idx) * sizeof(void *));
  vec->entries[new_idx] = tmp;

  return new_idx;
}

/**
 * \param[in] vec The vector to modify.
 * \param[in] idx1 The index of the first entry.
 * \param[in] idx2 The index of the second entry.
 * \return The index of the second entry or -1 on error.
 *
 * Swap two entries in the vector at \p idx1 and \p idx2 .
 */
int zt_vec_swap(zt_vec_t *vec, int idx1, int idx2) {
  void *tmp;

  if (unlikely(!vec || idx1 < 0 || idx1 >= vec->idx || idx2 < 0 || idx2 >= vec->idx))
    return -1;

  if (vec->sorted && vec->cmp && (vec->cmp(vec->entries[idx1], vec->entries[idx2]) != 0))
    vec->sorted = false;

  tmp = vec->entries[idx1];
  vec->entries[idx1] = vec->entries[idx2];
  vec->entries[idx2] = tmp;

  return idx2;
}

/**
 * \param[in] vec The vector to clear.
 *
 * Remove all entries from \p vec ,calling the destructor (if any) on each entry.
 * This doesn't free the vector itself.
 */
void zt_vec_clear(zt_vec_t *vec) {
  if (likely(vec)) {
    if (vec->destructor) {
      for (int i = 0; i < vec->idx; i++) {
        vec->destructor(vec->entries[i]);
        vec->entries[i] = NULL;
      }
    }
    vec->idx = 0;
    vec->sorted = true;
  }
}

/**
 * \param[in] vec The vector to clear.
 *
 * Remove all entries from \p vec without calling the destructor.
 */
void zt_vec_clear_nofree(zt_vec_t *vec) {
  if (likely(vec)) {
    for (int i = 0; i < vec->idx; i++)
      vec->entries[i] = NULL;
    vec->idx = 0;
    vec->sorted = true;
  }
}

/**
 * \param[in,out] vec Pointer to the vector to free.
 *
 * Free \p vec and all its entries.
 * The entries are freed using the destructor if one is set.
 * The vector pointer is set to NULL.
 */
void zt_vec_free(zt_vec_t **vec) {
  if (likely(vec && *vec)) {
    zt_vec_clear(*vec);
    zt_free((*vec)->entries);
    zt_free(*vec);
    *vec = NULL;
  }
}

/**
 * \param[out] dest The destination vector.
 * \param[in] src The source vector.
 * \return 0 on success, -1 on error.
 *
 * Create a deep copy of \p src into an already allocated vector \p dest .
 * Any entries in \p dest will be lost.
 */
int zt_vec_deepcopy(zt_vec_t *dest, zt_vec_t *src) {
  if (unlikely(!dest || !src))
    return -1;

  zt_vec_clear(dest);
  zt_free(dest->entries);

  dest->entries = zt_calloc(src->capacity, sizeof(void *));
  if (!dest->entries)
    return -1;

  memcpy(PTRV(dest), PTRV(src), sizeof(zt_vec_t));

  return 0;
}

/**
 * \param[in] vec The vector.
 * \return The number of entries in the vector or -1 on error.
 *
 * Get the number of entries in \p vec .
 */
int zt_vec_size(zt_vec_t *vec) {
  if (likely(vec))
    return vec->idx;
  return -1;
}

/**
 * \param[in] vec The vector.
 * \param[in] idx The index of the entry.
 * \return The entry at the specified index or NULL on error.
 *
 * Get the entry at \p idx in \p vec .
 */
void *zt_vec_get(zt_vec_t *vec, int idx) {
  if (likely(vec && idx >= 0 && idx < vec->idx))
    return vec->entries[idx];
  return NULL;
}

/**
 * \param[in] vec The vector to search.
 * \param[in] search_func The search function.
 * \param[in] search_arg The argument to pass to the search function.
 * \param[out] out Pointer to store the found entry (optional).
 * \return The index of the valid entry or -1 if not found.
 *
 * Search through every entry of \p vec until \p search_func returns `true`.
 *
 * \p search_func is called as `search_func(search_arg, entry)` on each element in the
 * vector's current order (i.e., not sorted before iterating).
 */
int zt_vec_search(zt_vec_t *vec, zt_vec_search_func_t *search_func,
                  const void *search_arg, void **out) {
  if (unlikely(!vec || !search_func))
    return -1;

  for (int i = 0; i < vec->idx; i++) {
    if (search_func(search_arg, vec->entries[i])) {
      if (out)
        *out = vec->entries[i];
      return i;
    }
  }

  return -1; /* `search_func` did not return `true` for any entry */
}

/**
 * \param[in] vec The vector to search.
 * \param[in] ele The memory to compare against.
 * \param[in] size The size of the memory to compare.
 * \param[out] out Pointer to store the found entry (optional).
 * \return The index of the found entry or -1 if not found.
 *
 * Search through every entry of \p vec using `memcmp` against memory pointed to by
 * \p ele of size \p size.
 *
 * If a match is found, the entry is stored in \p out (if not NULL) and the index is
 * returned.
 */
int zt_vec_find_memcmp(zt_vec_t *vec, const void *ele, size_t size, void **out) {
  if (unlikely(!vec || !ele || size == 0))
    return -1;

  for (int i = 0; i < vec->idx; i++) {
    if (memcmp(ele, vec->entries[i], size) == 0) {
      if (out)
        *out = vec->entries[i];
      return i;
    }
  }

  return -1; /* no match found */
}

/**
 * \param[in] vec The vector to search.
 * \param[in] ele The element to find.
 * \return The index of the found entry or -1 if not found.
 *
 * Find an entry in \p vec using its comparison function.
 * If one is not set, -1 is returned.
 */
int zt_vec_find(zt_vec_t *vec, const void *ele) {
  if (unlikely(!vec || !ele || !vec->cmp))
    return -1;

  if (vec->idx == 1) {
    if (vec->cmp(ele, vec->entries[0]) == 0)
      return 0;
  } else if (vec->sorted) {
    /* binary search for element */
    int l = 0, r = vec->idx - 1, m, cres;
    while (l <= r) {
      m = l + (r - l) / 2;
      cres = vec->cmp(ele, vec->entries[m]);
      if (cres == 0)
        return m;
      else
        (void)((cres > 0) ? (l = m + 1) : (r = m - 1));
    }
  } else {
    /* linear search */
    for (int i = 0; i < vec->idx; i++) {
      if (vec->cmp(ele, vec->entries[i]) == 0)
        return i;
    }
  }

  return -1; /* no match found */
}

/**
 * \param[in] vec The vector to search.
 * \param[in] ele The element to check for.
 * \return true if the element is found, false otherwise.
 *
 * Check if \p vec contains \p ele using the vector's comparison function.
 * If one is not set, false is returned.
 */
bool zt_vec_contains(zt_vec_t *vec, const void *ele) {
  return (zt_vec_find(vec, ele) >= 0);
}

/**
 * \param[in] vec The vector to search.
 * \param[in] ele The element to find (unused).
 * \param[in] start_idx The index to start searching from.
 * \param[in] direction The direction to search (positive for forward, negative for
 * backward).
 * \param[in] find_func The function to check each entry.
 * \return The index of the found entry or -1 if not found.
 *
 * Search through \p vec starting at \p start_idx in the specified \p direction (-1 for
 * backward, +1 for forward), calling \p find_func on each entry until it returns `true`.
 * If no match is found, -1 is returned.
 */
int zt_vec_find_ex(zt_vec_t *vec, const void *ele, int start_idx, int direction,
                   zt_vec_find_func_t *find_func) {
  if (unlikely(!vec || start_idx < 0 || start_idx >= vec->idx || direction == 0 ||
               !find_func))
    return -1;

  if (direction > 0) {
    /* left-to-right */
    for (int i = start_idx; i < vec->idx; i++) {
      if (find_func(vec->entries[i]))
        return i;
    }
  } else {
    /* right-to-left */
    for (int i = start_idx; i >= 0; i--) {
      if (find_func(vec->entries[i]))
        return i;
    }
  }
  return -1; /* no match found */
}

/**
 * \param[in] vec The vector to iterate over.
 * \param[in] iter_func The function to call for each entry.
 *
 * Call \p iter_func for each entry in \p vec in its current order.
 */
void zt_vec_iterate(zt_vec_t *vec, zt_vec_iter_func_t *iter_func) {
  if (likely(vec && iter_func)) {
    for (int i = 0; i < vec->idx; i++)
      iter_func(vec->entries[i]);
  }
}

/**
 * \param[in] vec The vector.
 * \param[in] destructor The destructor function.
 *
 * Set the destructor function for entries in this \p vec .
 */
void zt_vec_set_destructor(zt_vec_t *vec, zt_vec_iter_func_t *destructor) {
  if (likely(vec))
    vec->destructor = destructor;
}

/**
 * \param[in] vec The vector.
 * \param[in] cmp The comparison function.
 *
 * Set the comparison function for the entries in this \p vec .
 * If cmp is NULL, the vector cannot be sorted, and entries can only be retrieved via
 * their indices.
 */
void zt_vec_set_cmp_func(zt_vec_t *vec, zt_vec_cmp_func_t *cmp) {
  if (likely(vec)) {
    vec->cmp = cmp;
    vec->sorted = (cmp != NULL);
  }
}

/**
 * \param[in] vec The vector.
 * \param[in] factor The resize factor.
 *
 * Set the resize factor the \p vec .
 * When the vector is full and needs to grow, its capacity will be increased as
 * `new_size = old_size * factor`.
 * If `new_size <= old_size`, the vector size doesn't change and the calling function
 * fails.
 */
void zt_vec_set_resize_factor(zt_vec_t *vec, float factor) {
  if (likely(vec))
    vec->resize_factor = factor;
}

/**
 * \param[in] vec The vector to sort.
 *
 * Sort the entries in \p vec using its comparison function.
 */
void zt_vec_sort(zt_vec_t *vec) {
  if (likely(vec && vec->cmp && vec->idx > 1)) {
    qsort(vec->entries, vec->idx, sizeof(void *),
          (int (*)(const void *, const void *))vec->cmp);
    vec->sorted = true;
  }
}
