#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Definitions for uClibc's rand(3) implementation.
#include "uclibc/random.h"

// Configuration settings downloaded from the admin interface pretend to be a tar archive.
#define WEB_CONFIG_TAR_NAME "photos.tar"
// The real encrypted data is at this offset.
#define WEB_CONFIG_OFFSET 0xa0000

#define MAX_HEADER_AND_CONFIG_SIZE 0x39000

typedef struct config_header {
    uint32_t magic;
    uint32_t len;
    uint32_t crc;
} config_header;

int validate_checksum(config_header *config) {
    uint32_t len = config->len / sizeof(uint32_t);
    uint32_t crc = config->crc;
    config++;

    for (int i = 0; i < len; i++) {
        crc += config->magic;
        config = (config_header *) &config->len;
    }
    return crc == 0xffffffff;
}

int DecodeCFG(FILE *Decode) { // previously called 'f'
    unsigned char *buf = malloc(MAX_HEADER_AND_CONFIG_SIZE);
    if (!buf) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    fread(buf, strlen(WEB_CONFIG_TAR_NAME), 1, Decode);
    if (!memcmp(buf, WEB_CONFIG_TAR_NAME, strlen(WEB_CONFIG_TAR_NAME))) {
        if (fseek(Decode, WEB_CONFIG_OFFSET, SEEK_SET) < 0) {
            perror("fseek");
            return EXIT_FAILURE;
        }
    } else {
        rewind(Decode);
    }
    fread(buf, MAX_HEADER_AND_CONFIG_SIZE, 1, Decode);
    fclose(Decode);

    config_header *config = (config_header *) buf;
    if (config->len == 0 || config->len + sizeof(config_header) > MAX_HEADER_AND_CONFIG_SIZE) {
        fprintf(stderr, "invalid config length (0x%08x)\n", config->len);
        exit(-1);
    }

    // Seed given to uClibc srand() to generate XOR keystream.
    // Often 0x20131224 or 0x23091293.
    uclibc_srandom(config->magic);

    // XOR every 4 bytes with the next call to uClibc rand().
    uint32_t *p = (uint32_t *) (buf + sizeof(config_header));
    while (p < (uint32_t *) (buf + config->len + sizeof(config_header))) {
        *p = *p ^ uclibc_random();
        p++;
    }

    if (!validate_checksum(config)) {
        fprintf(stderr, "invalid checksum (0x%08x)\n", config->crc);
        exit(-1);
    }

    for (int i = sizeof(config_header); i < config->len + sizeof(config_header); i++) {
        if (buf[i] == '\0') {
            printf("\n");
        } else {
            printf("%c", buf[i]);
        }
    }

    free(buf);
    return EXIT_SUCCESS;
}

int EncodeCFG(FILE *Encode) { // Make sure to read the whole file into RAM before overwriting the file.
    perror("encoding not yet implemented");
    return EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
    /* -d decode <Settings.cfg> -e encode <Settings.cfg> */

    if (argc != 3) {
        fprintf(stderr, "Usage: (-d (decode) | -e (encode)) <Settings.cfg>\n");
        return EXIT_FAILURE;
    }

    if (strcasecmp(argv[1], "-d") == 0 || strcasecmp(argv[1], "-decode") == 0) { //  argv[1] == "-d"
        // Decode function call
        FILE *Decode = fopen(argv[2], "rb");
        if (!Decode) {
            perror(argv[2]);
            return EXIT_FAILURE;
        }

        DecodeCFG(Decode);
    } else if (strcasecmp(argv[1], "-e") == 0 || strcasecmp(argv[1], "-encode") == 0) {
        // Encode function call
        FILE *Encode = fopen(argv[2], "rb");
        if (!Encode) {
            perror(argv[2]);
            return EXIT_FAILURE;
        }

        EncodeCFG(Encode);
    } else {
        fprintf(stderr, "Unknown argument: '%s'\n", argv[1]);
    }

    return EXIT_SUCCESS;
}
