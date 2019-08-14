#include "cbc.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/random.h>

#define KEY_LENGTH 16 /* Key length in bytes = 128 / 8. */

int main(int argc, char *argv[]) {
    uint8_t key[KEY_LENGTH];
    char *filename;
    FILE *f;

    if (argc != 2) {
        printf("Usage: %s filename\n", argv[0]);
        return 0;
    }

    filename = argv[1];
    f = fopen(filename, "w");
    if (f == NULL) {
        printf("Error creating file \"%s\"\n", filename);
        return 1;
    }

    /* Generate random key */
    if (getrandom(key, KEY_LENGTH, GRND_NONBLOCK) != KEY_LENGTH) {
        printf("Error while trying to generate the key\n");
        exit(1);
    }

    /* Write the key to the file */
    for (int i = 0; i < KEY_LENGTH; ++i) {
        fprintf(f, "%02x", key[i]);
    }
    fprintf(f, "\n");

    fclose(f);

    return 0;
}
