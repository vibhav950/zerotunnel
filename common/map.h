#ifndef __MAP_H__
#define __MAP_H__

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MAP_DEFAULT_CAPACITY 20
#define MAP_MAX_LOAD_FACTOR 0.75
// #define MAP_RESIZE_FACTOR 1.5

struct __bucket {
  struct __bucket *next;
  const void *key;
  size_t ksize;
  uint32_t hash;
  void *value;
};

typedef struct _zt_map_st {
  struct __bucket *buckets;
  int capacity;
  int count;
#ifdef __HASHMAP_REMOVABLE
  int tombstone_count; // empty buckets from removed elements
#endif
  struct __bucket *first; // ordered linked list of valid entries
  struct __bucket *last;  // where to add the next element
} zt_map_t;

#define zt_map_str_lit(str) (str), sizeof(str) - 1
#define zt_map_static_arr(arr) (arr), sizeof(arr)

/**
 * Callback type for iterating over a map/freeing entries.
 * \p usr is a user pointer which can be passed through \p zt_map_iterate().
 */
typedef int (*zt_map_cb_func_t)(const void *key, size_t ksize, void *value, void *usr);

/** Create a new map */
zt_map_t *zt_map_create(void);

/**
 * Only frees the hashmap object and buckets.
 * Does not call zt_free() on each element's \p key or \p value.
 * To free data associated with an element, call \p hashmap_iterate().
 */
void zt_map_free(zt_map_t *map);

/**
 * Does not make a copy of \p key.
 * You must copy it yourself if you want to guarantee its lifetime,
 * or if you intend to call \p hashmap_key_free().
 * Returns -1 on error.
 */
int zt_map_set(zt_map_t *map, const void *key, size_t ksize, void *value);

/**
 * Adds an entry if it doesn't exist, using the value of \p *out_in.
 * If it does exist, it sets the value of \p *out_in, meaning the
 * value of the existing entry will be placed in \p *out_in regardless
 * of whether or not it existed in the first place.
 * Returns -1 on error.
 * Returns 1 if the entry already existed.
 * Returns 0 otherwise.
 */
int zt_map_get_set(zt_map_t *map, const void *key, size_t kszie, void **out_in);

/**
 * Similar to \p zt_map_set(), but when overwriting an entry,
 * You'll be able properly free the old entry's data via a callback.
 * Unlike \p zt_map_set(), this function will overwrite the original key
 * pointer, which means you can free the old key in the callback if applicable.
 */
int zt_map_set_free(zt_map_t *map, const void *key, size_t ksize, void *value,
                    zt_map_cb_func_t cb, void *usr);

int zt_map_get(zt_map_t *map, const void *key, size_t ksize, void **out_val);

#ifdef __HASHMAP_REMOVABLE
void zt_map_remove(zt_map_t *map, const void *key, size_t ksize);

/**
 * Same as \p zt_map_remove(), but it allows you to free an entry's data first
 * via a callback.
 */
void zt_map_remove_free(zt_map_t *m, const void *key, size_t ksize, zt_map_cb_func_t cb,
                        void *usr);
#endif

int zt_map_size(zt_map_t *map);

/**
 * Iterate over the map, calling \p cb on every element.
 * Goes through elements in the order they were added.
 * The element's key, key size, value, and \p usr will be passed to \p cb.
 * If \p cb returns -1 the iteration is aborted.
 * Returns the last result of \p cb.
 */
int zt_map_iterate(zt_map_t *map, zt_map_cb_func_t cb, void *usr);

/**
 * Dumps bucket info for debugging.
 * Allows you to see how many collisions you are getting.
 * `0` is an empty bucket, `1` is occupied, and `x` is removed.
 */
// void bucket_dump(hashmap *m);

#endif // __MAP_H__
