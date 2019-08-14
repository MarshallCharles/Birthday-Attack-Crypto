#include "tczero.h"
#include "cbc.h"
#include "hashmap.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/random.h>

#define BLOCK_MASK ((HALF_BLOCK_SIZE * 2 == 64) ? ~0ull : (1ull << (HALF_BLOCK_SIZE * 2)) - 1)

/* Global variables used mainly to respect the 'attack' given signature */
int verbose = 0;
long num_encryptions = 0;
char *key_file = "key.txt";

void print_usage(char *progname) {
    printf("Usage: %s [--verbose] [-n N] <key file> <text file>\n", progname);
    exit(0);
}

/* Performs the birthday attack on CBC for a block size <= 64.
 *
 * It returns the plaintext of the block on which the collision happened.
 */
uint64_t attack(uint8_t *ct, size_t ctlen) {
    hashmap *map = hashmap_create(((size_t) 1) << (HALF_BLOCK_SIZE + 1));
    uint8_t pt_block[128 / 8], *ct2;
    uint8_t *prev_ct_block1, *next_ct_block1;
    uint8_t *prev_ct_block2, *next_ct_block2;
    uint64_t key[2];
    uint64_t a = 0, b = 0;
    size_t ptlen, ctlen2;
    int num_blocks = ctlen / BYTES_PER_BLOCK;
    int i, collision = 0;
    read_key(key_file, key);
    num_encryptions = 0;

    /* Fill the map with the ciphertext blocks as values and their succressors
     * as keys */
    for (i = 1; i < num_blocks; i++) {
        ++num_encryptions;
        prev_ct_block1 = ct + BYTES_PER_BLOCK * (i - 1);
        next_ct_block1 = ct + BYTES_PER_BLOCK * i;
        /* Collision */
        if (contains(map, next_ct_block1)) {
            if (verbose) {
                printf("Collision found on cipher text block #%d\n", i);
            }

            prev_ct_block2 = (uint8_t *) get_value(map, next_ct_block1);
            a = *((uint64_t *) prev_ct_block1);
            b = *((uint64_t *) prev_ct_block2);

            hashmap_free(map);
            return (a ^ b) & BLOCK_MASK;
        }
        put(map, next_ct_block1, prev_ct_block1);
    }

    ptlen = BYTES_PER_BLOCK;
    ctlen2 = 0;

    /* Encrypt the plaintext block until a collision is found */
    while (1) {
        ++num_encryptions;
        /* Generate random block to encrypt */
        if (getrandom(pt_block, BYTES_PER_BLOCK, GRND_NONBLOCK) != BYTES_PER_BLOCK) {
            printf("Error while trying to generate the IV\n");
            exit(1);
        }

        allocate_ciphertext(ptlen, &ct2, &ctlen2);
        cbc_enc(key, pt_block, ct2, ptlen);
        prev_ct_block2 = ct2;
        next_ct_block2 = ct2 + BYTES_PER_BLOCK;
        /* Collision */
        if (contains(map, next_ct_block2)) {
            if (verbose) {
                printf("Collision found after encrypting %ld blocks\n", num_encryptions);
            }

            prev_ct_block1 = (uint8_t *) get_value(map, next_ct_block2);
//            memcpy(&a, prev_ct_block1, BYTES_PER_BLOCK);
            a = *((uint64_t *) prev_ct_block1);
            b = *((uint64_t *) prev_ct_block2);

            free(ct2);
            hashmap_free(map);
            return (a ^ b) & BLOCK_MASK;
        }
        put(map, next_ct_block2, prev_ct_block2);
    }
}

int main(int argc, char *argv[]) {
    uint64_t key[2];
    uint64_t decrypted_block;
    char *plaintext;
    uint8_t *ciphertext;
    size_t ptlen = 0;
    size_t ctlen = 0;
    long total_encryptions;
    int i, N = 1;
    int argi = 1;
    char *txt_file;
    clock_t start_time, end_time;
    double duration, total_duration;

    /* Parse arguments */
    if ((argc < 3) || (argc > 6)) {
        print_usage(argv[0]);
    }
    while (argi < argc - 2) {
        if (strcmp(argv[argi], "--verbose") == 0) {
            verbose = 1;
            ++argi;
        } else if (strcmp(argv[argi], "-n") == 0) {
            N = atoi(argv[++argi]);
            ++argi;
        } else {
            break;
        }
    }
    if (argi != argc - 2) {
        print_usage(argv[0]);
    }
    key_file = argv[argi++];
    txt_file = argv[argi++];

    read_key(key_file, key);
    printf("Key: ");
    print_hex((uint8_t *) key, 128 / 8, "", "\n");
    printf("\n");

    read_text_file(txt_file, &plaintext, &ptlen);
    printf("\n");

    allocate_ciphertext(ptlen, &ciphertext, &ctlen);

    /* Compute the average number of encryptions required for N attacks */
    total_encryptions = 0;
    total_duration = 0.0;
    for (i = 0; i < N; ++i) {
        cbc_enc(key, plaintext, ciphertext, ptlen);
        /* Perform the attack and record the time and number of encryptions */
        start_time = clock();
        decrypted_block = attack(ciphertext, ctlen);
        end_time = clock();
        duration = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

        if (verbose) {
            printf("Collision found after %.2e s\n", duration);
            printf("Messages XOR: ");
            print_hex((uint8_t *) (&decrypted_block), BYTES_PER_BLOCK, " ", "\n");
        }

        total_duration += duration;
        total_encryptions += num_encryptions;
    }
    printf("Average number of encryptions: %.2f\n", (double) total_encryptions / (double) N);
    printf("Average attack time: %.2e s\n", total_duration / N);

    free(ciphertext);
    free(plaintext);
    return 0;
}
