#include "tczero.h"
#include "cbc.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>

#define MASK ((HALF_BLOCK_SIZE == 64) ? ~0ull : (1ull << (HALF_BLOCK_SIZE)) - 1)

/* Copies the half block in array into the Least Significant Bits of x. */
void block_to_uint64(uint8_t *array, uint64_t *x) {
    memcpy(x, array, BYTES_PER_HALF_BLOCK);
    *x = (*x) & MASK;
}

/* Copies the HALF_BLOCK_SIZE Least Significant Bits of x into array. */
void uint64_to_block(uint64_t x, uint8_t *array) {
    memcpy(array, &x, BYTES_PER_HALF_BLOCK);
}

/* Encrypts the given plaintext with a random IV.
 *
 * The returned value (ct) is the IV concataaated with the ciphertext.
 */
void cbc_enc(uint64_t key[2], uint8_t *pt, uint8_t *ct, size_t ptlen) {
    /* Buffer block used to encrypt data */
    uint64_t x[2];
    /* Temporary variables used for local computations */
    uint64_t y = 0;
    uint64_t z = 0;
    /* The current block being encrypted */
    uint8_t *ptblock = pt;
    /* The current resulting ciphertext block */
    uint8_t *ctblock = ct + BYTES_PER_BLOCK;
    /* The previous ciphertext block to be XORed with the plaintext block */
    uint8_t *prev_ct = ct;

    /* Number of blocks to be encrypted */
    unsigned int numblocks = ptlen / BYTES_PER_BLOCK;
    int i, j, k;

    /* Generate IV inside the first ciphertext block */
    if (getrandom(prev_ct, BYTES_PER_BLOCK, GRND_NONBLOCK) != BYTES_PER_BLOCK) {
        printf("Error while trying to generate the IV\n");
        exit(1);
    }

    for (i = 0; i < numblocks; i++) {
        /* XOR the message block with the ciphertext block */
        for (j = 0; j < 2; j++) {
            block_to_uint64(ptblock, &y);
            block_to_uint64(prev_ct, &z);
            x[j] = y ^ z;
            ptblock = ptblock + BYTES_PER_HALF_BLOCK;
            prev_ct = prev_ct + BYTES_PER_HALF_BLOCK;
        }
        /* Encrypts the XORed block */
        tc0_encrypt(x, key);
        /* Copy the encrypted data into the ciphertext */
        for (j = 0; j < 2; j++) {
            uint64_to_block(x[j], ctblock);
            ctblock = ctblock + BYTES_PER_HALF_BLOCK;
        }
    }
}

/* Decrypts the given ciphertext. */
void cbc_dec(uint64_t key[2], uint8_t *ct, uint8_t *pt, size_t ctlen) {
    /* Buffer block used to decrypt data */
    uint64_t x[2];
    /* Temporary variables used for local computations */
    uint64_t y = 0;
    uint64_t z = 0;
    /* The current block being decrypted */
    uint8_t *ctblock = ct + BYTES_PER_BLOCK;
    /* The current resulting plaintext block */
    uint8_t *ptblock = pt;
    /* The previous ciphertext block to be XORed with the decrypted block */
    uint8_t *prev_ct = ct;

    /* Number of blocks to be decrypted. It's the total number of block minus the IV. */
    unsigned int numblocks = ctlen / BYTES_PER_BLOCK - 1;
    int i, j, k;

    for (i = 0; i < numblocks; i++) {
        /* Copy the ciphertext block to x */
        for (j = 0; j < 2; j++) {
            block_to_uint64(ctblock, x + j);
            ctblock = ctblock + BYTES_PER_HALF_BLOCK;
        }
        /* Decrypt the ciphertext block */
        tc0_decrypt(x, key);
        /* XOR the decrypted block with the previous ciphertext block */
        for (j = 0; j < 2; j++) {
            block_to_uint64(prev_ct, &y);
            z = x[j] ^ y;
            uint64_to_block(z, ptblock);
            ptblock = ptblock + BYTES_PER_HALF_BLOCK;
            prev_ct = prev_ct + BYTES_PER_HALF_BLOCK;
        }
    }
}

void allocate_ciphertext(size_t ptlen, uint8_t **ciphertext, size_t *ctlen) {
    *ctlen = ptlen + BYTES_PER_BLOCK;
    *ciphertext = (uint8_t *) malloc(*ctlen * sizeof(uint8_t));
}

void allocate_plaintext(size_t ctlen, uint8_t **plaintext, size_t *ptlen) {
    *ptlen = ctlen - BYTES_PER_BLOCK;
    *plaintext = (uint8_t *) malloc(*ptlen * sizeof(char));
}

void print_hex(uint8_t *hex_str, size_t length, char *sep, char *end) {
    unsigned int i;

    if (length > 0) {
        printf("%02x", hex_str[0]);
    }
    for (i = 1; i < length; ++i) {
        printf("%s%02x", sep, hex_str[i]);
    }
    printf("%s", end);
}

void read_key(char *filename, uint64_t key[2]) {
    unsigned char *char_key = (unsigned char *) key;
    unsigned int hex;
    unsigned int i;
    FILE *f = fopen(filename, "r");

    if (f == NULL) {
        printf("Error reading file \"%s\"\n", filename);
        exit(1);
    }

    for (i = 0; i < 128 / 8; ++i) {
        fscanf(f, "%02x", &hex);
        char_key[i] = (unsigned char) hex;
    }

    fclose(f);
}

void read_text_file(char *filename, char **text, size_t *ptlen) {
    char *buffer;
    long length, adjusted_length, i;
    FILE *f = fopen(filename, "r");

    if (f == NULL) {
        printf("Error reading file '%s'\n", filename);
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    length = ftell(f);
    adjusted_length = (((length + 1) + (BYTES_PER_BLOCK - 1)) / BYTES_PER_BLOCK) * BYTES_PER_BLOCK;
    fseek(f, 0, SEEK_SET);
    buffer = (char *) malloc(adjusted_length * sizeof(char));
    fread(buffer, 1, length, f);
    for (i = length; i < adjusted_length; ++i) {
        buffer[i] = '\0';
    }
    printf("Read %ld chars from file '%s' into a buffer of size %ld\n", length, filename, adjusted_length);

    *text = buffer;
    *ptlen = adjusted_length;

    fclose (f);
}
