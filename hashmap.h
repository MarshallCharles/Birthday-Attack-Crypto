#ifndef __HASHMAP_H__
#define __HASHMAP_H__

#include <stdint.h>

typedef struct hashmap hashmap;

hashmap* hashmap_create(size_t initial_capacity);

void hashmap_free(hashmap *map);

int contains(hashmap *map, uint8_t *key);

void* get_value(hashmap *map, uint8_t *key);

void put(hashmap *map, uint8_t *key, void *value);

#endif /* __HASHMAP_H__ */
