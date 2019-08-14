#include "cbc.h"
#include "hashmap.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define THRESHOLD          0.8
#define INITIAL_CAPACITY   16

typedef struct hashnode hashnode;

struct hashnode {
    uint8_t *key;
    void *value;
    struct hashnode *next;
};

struct hashmap {
    size_t size;
    size_t load;
    size_t capacity;
    hashnode **buckets;
};

/******************************************************************************/
/* Helper functions                                                           */
/******************************************************************************/

hashnode* hashnode_create(uint8_t *key, void *value) {
    hashnode *node = (hashnode *) malloc(sizeof(hashnode));
    node->key = key;
    node->value = value;
    node->next = NULL;
    return node;
}

void init_map(hashmap *map, int capacity) {
    int i;
    map->size = 0;
    map->load = 0;
    map->capacity = capacity;
    map->buckets = (hashnode **) malloc(map->capacity * sizeof(hashnode *));
    for (i = 0; i < map->capacity; ++i) {
        map->buckets[i] = NULL;
    }
}

uint32_t hashcode(uint8_t *key) {
    uint32_t hash = 1;
    uint32_t val = 0;
    int num_bits = HALF_BLOCK_SIZE * 2;
    while (num_bits >= 32) {
        memcpy(&val, key, 4);
        hash = hash * 37 + val;
        num_bits -= 32;
        key = key + 4;
    }
    memcpy(&val, key, num_bits / 8);
    val = val & ((1 << num_bits) - 1);
    hash = hash * 37 + val;
    return hash;
}

int equals_key(uint8_t *key1, uint8_t *key2) {
    int result = 1;
    int num_bits = HALF_BLOCK_SIZE * 2;
    uint64_t b1 = 0, b2 = 0;
    while (num_bits >= 64) {
        memcpy(&b1, key1, 8);
        memcpy(&b2, key2, 8);
        result = result & (b1 == b2);
        num_bits -= 64;
        b1 = b1 + 8;
        b2 = b2 + 8;
    }
    b1 = 0;
    b2 = 0;
    memcpy(&b1, key1, num_bits >> 3);
    memcpy(&b2, key2, num_bits >> 3);
    result = result & (b1 == b2);
    return result;
}

hashnode* get_node(hashmap *map, uint8_t *key) {
    uint32_t hash = hashcode(key);
    hashnode *node = map->buckets[hash % map->capacity];
    while (node != NULL) {
        if (equals_key(node->key, key)) {
            return node;
        }
        node = node->next;
    }
    return NULL;
}

void resize(hashmap *map) {
    int i;
    int old_capacity = map->capacity;
    hashnode *curr_node, *prev_node;
    hashnode **old_buckets = map->buckets;
    init_map(map, old_capacity * 2);
    for (i = 0; i < old_capacity; ++i) {
        curr_node = old_buckets[i];
        while (curr_node != NULL) {
            put(map, curr_node->key, curr_node->value);
            prev_node = curr_node;
            curr_node = curr_node->next;
            free(prev_node);
        }
    }
    free(old_buckets);
}

/******************************************************************************/

hashmap* hashmap_create(size_t initial_capacity) {
    hashmap *map = (hashmap *) malloc(sizeof(hashmap));
    init_map(map, initial_capacity);
    return map;
}

void hashmap_free(hashmap *map) {
    int i;
    hashnode *curr_node, *next_node;
    for (i = 0; i < map->capacity; ++i) {
        curr_node = map->buckets[i];
        while (curr_node != NULL) {
            next_node = curr_node->next;
            free(curr_node);
            curr_node = next_node;
        }
    }
    free(map->buckets);
    free(map);
}

int contains(hashmap *map, uint8_t *key) {
    return get_node(map, key) != NULL;
}

void* get_value(hashmap *map, uint8_t *key) {
    return get_node(map, key)->value;
}

void put(hashmap *map, uint8_t *key, void *value) {
    uint32_t hash;
    hashnode *node = get_node(map, key);
    if (node == NULL) {
        hash = hashcode(key);
        ++(map->size);
        if (map->buckets[hash % map->capacity] == NULL) {
            ++(map->load);
        }
        node = hashnode_create(key, value);
        node->next = map->buckets[hash % map->capacity];
        map->buckets[hash % map->capacity] = node;
        if (map->load >= THRESHOLD * map->capacity) {
            resize(map);
        }
    } else {
        node->value = value;
    }
}
