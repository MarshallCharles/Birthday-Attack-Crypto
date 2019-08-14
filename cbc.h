#ifndef __CBC_H__
#define __CBC_H__

#include "tczero.h"
#include <stdlib.h>
#include <stdint.h>

#define BYTES_PER_HALF_BLOCK   (HALF_BLOCK_SIZE / 8)
#define BYTES_PER_BLOCK        (BYTES_PER_HALF_BLOCK * 2)

void cbc_enc(uint64_t key[2], uint8_t *pt, uint8_t *ct, size_t ptlen);

void cbc_dec(uint64_t key[2], uint8_t *ct, uint8_t *pt, size_t ctlen);

void allocate_ciphertext(size_t ptlen, uint8_t **ciphertext, size_t *ctlen);

void allocate_plaintext(size_t ctlen, uint8_t **plaintext, size_t *ptlen);

void print_hex(uint8_t *hex_str, size_t length, char *sep, char *end);

void read_key(char *filename, uint64_t key[2]);

void read_text_file(char *filename, char **text, size_t *ptlen);

#endif /* __CBC_H__ */
