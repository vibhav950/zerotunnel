/**
 * Original implementation by Mashpoe [GitHub]
 * https://github.com/Mashpoe/c-hashmap/blob/main/map.c
 *
 * Modified by vibhav950 for zerotunnel.
 */

#include "map.h"
#include "defines.h"

#include <string.h>

// #include <stdio.h>

zt_map_t *zt_map_create(void) {
  zt_map_t *m = zt_malloc(sizeof(zt_map_t));
  if (m == NULL)
    return NULL;

  m->capacity = MAP_DEFAULT_CAPACITY;
  m->count = 0;

#ifdef __HASHMAP_REMOVABLE
  m->tombstone_count = 0;
#endif

  m->buckets = zt_calloc(MAP_DEFAULT_CAPACITY, sizeof(struct __bucket));
  if (m->buckets == NULL) {
    zt_free(m);
    return NULL;
  }

  m->first = NULL;

  // this prevents branching in hashmap_set.
  // m->first will be treated as the "next" pointer in an imaginary bucket.
  // when the first item is added, m->first will be set to the correct address.
  m->last = (struct __bucket *)&m->first;
  return m;
}

void zt_map_free(zt_map_t *m) {
  zt_free(m->buckets);
  zt_free(m);
}

// puts an old bucket into a resized hashmap
static struct __bucket *resize_entry(zt_map_t *m, struct __bucket *old_entry) {
  uint32_t index = old_entry->hash % m->capacity;
  for (;;) {
    struct __bucket *entry = &m->buckets[index];

    if (entry->key == NULL) {
      *entry = *old_entry; // copy data from old entry
      return entry;
    }

    index = (index + 1) % m->capacity;
  }
}

static int hashmap_resize(zt_map_t *m) {
  int old_capacity = m->capacity;
  struct __bucket *old_buckets = m->buckets;

  // resize by 50% + 1; this handles capacity = 1
  m->capacity = m->capacity + m->capacity / 2 + 1;
  // initializes all bucket fields to null
  m->buckets = zt_calloc(m->capacity, sizeof(struct __bucket));
  if (m->buckets == NULL) {
    m->capacity = old_capacity;
    m->buckets = old_buckets;
    return -1;
  }

  // same trick; avoids branching
  m->last = (struct __bucket *)&m->first;

#ifdef __HASHMAP_REMOVABLE
  m->count -= m->tombstone_count;
  m->tombstone_count = 0;
#endif

  // assumes that an empty map won't be resized
  do {
#ifdef __HASHMAP_REMOVABLE
    // skip entry if it's a "tombstone"
    struct __bucket *current = m->last->next;
    if (current->key == NULL) {
      m->last->next = current->next;
      // skip to loop condition
      continue;
    }
#endif

    m->last->next = resize_entry(m, m->last->next);
    m->last = m->last->next;
  } while (m->last->next != NULL);

  zt_free(old_buckets);
  return 0;
}

#define HASHMAP_HASH_INIT 2166136261u

// FNV-1a hash function
static inline uint32_t hash_data(const unsigned char *data, size_t size) {
  size_t nblocks = size / 8;
  uint64_t hash = HASHMAP_HASH_INIT;
  for (size_t i = 0; i < nblocks; ++i) {
    hash ^= (uint64_t)data[0] << 0 | (uint64_t)data[1] << 8 |
            (uint64_t)data[2] << 16 | (uint64_t)data[3] << 24 |
            (uint64_t)data[4] << 32 | (uint64_t)data[5] << 40 |
            (uint64_t)data[6] << 48 | (uint64_t)data[7] << 56;
    hash *= 0xbf58476d1ce4e5b9;
    data += 8;
  }

  uint64_t last = size & 0xff;
  switch (size % 8) {
  case 7:
    last |= (uint64_t)data[6] << 56;
    ATTRIBUTE_FALLTHROUGH;
  case 6:
    last |= (uint64_t)data[5] << 48;
    ATTRIBUTE_FALLTHROUGH;
  case 5:
    last |= (uint64_t)data[4] << 40;
    ATTRIBUTE_FALLTHROUGH;
  case 4:
    last |= (uint64_t)data[3] << 32;
    ATTRIBUTE_FALLTHROUGH;
  case 3:
    last |= (uint64_t)data[2] << 24;
    ATTRIBUTE_FALLTHROUGH;
  case 2:
    last |= (uint64_t)data[1] << 16;
    ATTRIBUTE_FALLTHROUGH;
  case 1:
    last |= (uint64_t)data[0] << 8;
    hash ^= last;
    hash *= 0xd6e8feb86659fd93;
  }

  // compress to a 32-bit result.
  // also serves as a finalizer.
  return (uint32_t)(hash ^ hash >> 32);
}

static struct __bucket *find_entry(zt_map_t *m, const void *key, size_t ksize,
                                   uint32_t hash) {
  uint32_t index = hash % m->capacity;

  for (;;) {
    struct __bucket *entry = &m->buckets[index];

#ifdef __HASHMAP_REMOVABLE

    // compare sizes, then hashes, then key data as a last resort.
    // check for tombstone
    if ((entry->key == NULL && entry->value == 0) ||
        // check for valid matching entry
        (entry->key != NULL && entry->ksize == ksize && entry->hash == hash &&
         memcmp(entry->key, key, ksize) == 0)) {
      // return the entry if a match or an empty bucket is found
      return entry;
    }

#else

    // kind of a thicc condition;
    // I didn't want this to span multiple if statements or functions.
    if (entry->key == NULL ||
        // compare sizes, then hashes, then key data as a last resort.
        (entry->ksize == ksize && entry->hash == hash &&
         memcmp(entry->key, key, ksize) == 0)) {
      // return the entry if a match or an empty bucket is found
      return entry;
    }
#endif

    // printf("collision\n");
    index = (index + 1) % m->capacity;
  }
}

int zt_map_set(zt_map_t *m, const void *key, size_t ksize, void *val) {
  if (m->count + 1 > MAP_MAX_LOAD_FACTOR * m->capacity) {
    if (hashmap_resize(m) == -1)
      return -1;
  }

  uint32_t hash = hash_data(key, ksize);
  struct __bucket *entry = find_entry(m, key, ksize, hash);
  if (entry->key == NULL) {
    m->last->next = entry;
    m->last = entry;
    entry->next = NULL;

    ++m->count;

    entry->key = key;
    entry->ksize = ksize;
    entry->hash = hash;
  }
  entry->value = val;
  return 0;
}

int zt_map_get_set(zt_map_t *m, const void *key, size_t ksize, void **out_in) {
  if (m->count + 1 > MAP_MAX_LOAD_FACTOR * m->capacity) {
    if (hashmap_resize(m) == -1)
      return -1;
  }

  uint32_t hash = hash_data(key, ksize);
  struct __bucket *entry = find_entry(m, key, ksize, hash);
  if (entry->key == NULL) {
    m->last->next = entry;
    m->last = entry;
    entry->next = NULL;

    ++m->count;

    entry->value = *out_in;
    entry->key = key;
    entry->ksize = ksize;
    entry->hash = hash;

    return 0;
  }
  *out_in = entry->value;
  return 1;
}

int zt_map_set_free(zt_map_t *m, const void *key, size_t ksize, void *val,
                    zt_map_cb_func_t c, void *usr) {
  if (m->count + 1 > MAP_MAX_LOAD_FACTOR * m->capacity) {
    if (hashmap_resize(m) == -1)
      return -1;
  }

  uint32_t hash = hash_data(key, ksize);
  struct __bucket *entry = find_entry(m, key, ksize, hash);
  if (entry->key == NULL) {
    m->last->next = entry;
    m->last = entry;
    entry->next = NULL;

    ++m->count;

    entry->key = key;
    entry->ksize = ksize;
    entry->hash = hash;
    entry->value = val;
    // there was no overwrite, exit the function.
    return 0;
  }
  // allow the callback to zt_free() the entry data.
  // use old key and value so the callback can zt_free() them.
  // the old key and value will be overwritten after this call.
  int error = c(entry->key, ksize, entry->value, usr);

  // overwrite the old key pointer in case the callback zt_free-s it.
  entry->key = key;
  entry->value = val;
  return error;
}

int zt_map_get(zt_map_t *m, const void *key, size_t ksize, void **out_val) {
  uint32_t hash = hash_data(key, ksize);
  struct __bucket *entry = find_entry(m, key, ksize, hash);

  // if there is no match, output val will just be NULL
  *out_val = entry->value;

  return entry->key != NULL ? 1 : 0;
}

#ifdef __HASHMAP_REMOVABLE
// doesn't "remove" the element per se, but it will be ignored.
// the element will eventually be removed when the map is resized.
void zt_map_remove(zt_map_t *m, const void *key, size_t ksize) {
  uint32_t hash = hash_data(key, ksize);
  struct __bucket *entry = find_entry(m, key, ksize, hash);

  if (entry->key != NULL) {

    // "tombstone" entry is signified by a NULL key with a nonzero value
    // element removal is optional because of the overhead of tombstone checks
    entry->key = NULL;
    entry->value = 0xDEAD; // I mean, it's a tombstone...

    ++m->tombstone_count;
  }
}

void zt_map_remove_free(zt_map_t *m, const void *key, size_t ksize,
                        zt_map_cb_func_t c, void *usr) {
  uint32_t hash = hash_data(key, ksize);
  struct __bucket *entry = find_entry(m, key, ksize, hash);

  if (entry->key != NULL) {
    c(entry->key, entry->ksize, entry->value, usr);

    // "tombstone" entry is signified by a NULL key with a nonzero value
    // element removal is optional because of the overhead of tombstone checks
    entry->key = NULL;
    entry->value = 0xDEAD; // I mean, it's a tombstone...

    ++m->tombstone_count;
  }
}
#endif

int zt_map_size(zt_map_t *m) {

#ifdef __HASHMAP_REMOVABLE
  return m->count - m->tombstone_count;
#else
  return m->count;
#endif
}

int zt_map_iterate(zt_map_t *m, zt_map_cb_func_t cb, void *user_ptr) {
  // loop through the linked list of valid entries
  // this way we can skip over empty buckets
  struct __bucket *current = m->first;
  int error = 0;

  while (current != NULL) {
#ifdef __HASHMAP_REMOVABLE
    // "tombstone" check
    if (current->key != NULL)
#endif
      error = cb(current->key, current->ksize, current->value, user_ptr);
    if (error == -1)
      break;

    current = current->next;
  }
  return error;
}

/* void bucket_dump(zt_map_t *m) {
  for (int i = 0; i < m->capacity; i++) {
    if (m->buckets[i].key == NULL)
      if (m->buckets[i].value != 0)
        printf("x");
      else
        printf("0");
    else
      printf("1");
  }
  printf("\n");
  fflush(stdout);
} */
