#include "tczero.h"
#include "cbc.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void print_usage(char *progname) {
    printf("Usage: %s [--verbose] <key file> <text file>\n", progname);
    exit(0);
}

int verify_non_deterministic(uint8_t *plaintext, size_t ptlen, uint64_t *key, int verbose) {
    uint8_t *ciphertext1;
    uint8_t *ciphertext2;
    size_t ctlen = 0;
    int result = 0;
    int i;

    allocate_ciphertext(ptlen, &ciphertext1, &ctlen);
    allocate_ciphertext(ptlen, &ciphertext2, &ctlen);

    cbc_enc(key, plaintext, ciphertext1, ptlen);
    cbc_enc(key, plaintext, ciphertext2, ptlen);

    if (verbose) {
        printf("Encryption 1: ");
        print_hex(ciphertext1, ctlen, "", "\n");
        printf("Encryption 2: ");
        print_hex(ciphertext2, ctlen, "", "\n");
        printf("\n");
    }

    for (i = 0; i < ctlen; i++) {
        if (ciphertext1[i] != ciphertext2[i]) {
            result = 1;
            break;
        }
    }

    free(ciphertext2);
    free(ciphertext1);
    return result;
}

int verify_proper_decryption(uint8_t *plaintext, size_t ptlen, uint64_t *key, int verbose) {
    uint8_t *ciphertext;
    uint8_t *plaintext2;
    size_t ctlen = 0;
    size_t ptlen2 = 0;
    int result;

    allocate_ciphertext(ptlen, &ciphertext, &ctlen);
    cbc_enc(key, plaintext, ciphertext, ptlen);

    allocate_plaintext(ctlen, &plaintext2, &ptlen2);
    cbc_dec(key, ciphertext, plaintext2, ctlen);

    if (verbose) {
        printf("The original plaintext:   '%s'\n", plaintext);
        printf("The decrypted ciphertext: '%s'\n", plaintext2);
        printf("\n");
    }

    result = (strcmp(plaintext, plaintext2) == 0);
    free(plaintext2);
    free(ciphertext);
    return result;
}

int main(int argc, char *argv[]) {
    uint64_t key[2];
    char *plaintext;
    size_t ptlen = 0;
    size_t ctlen = 0;
    int verbose = 0;
    int argi = 1;
    char *key_file;
    char *txt_file;

    /* Parse arguments */
    if (argc == 4) {
        if (strcmp(argv[argi++], "--verbose") == 0) {
            verbose = 1;
        } else {
            print_usage(argv[0]);
        }
    }
    if ((argc < 3) || (argc > 4)) {
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

    if (verify_non_deterministic(plaintext, ptlen, key, verbose)) {
        printf("Ciphertexts non-deterministic: OK\n");
    } else {
        printf("Ciphertexts non-deterministic: not OK, something is wrong...\n");
    }
    printf("\n");

    if (verify_proper_decryption(plaintext, ptlen, key, verbose)) {
        printf("Proper encryption/decryption:  OK\n");
    } else {
        printf("Proper encryption/decryption:  not OK, something is wrong...\n");
    }
    printf("\n");

    free(plaintext);
    return 0;
}
