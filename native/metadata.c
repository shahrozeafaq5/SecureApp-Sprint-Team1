#include <stdio.h>
#include <string.h>

/*
 * Secure Metadata Parser
 * Remediated according to CERT C Coding Standard (STR31-C, ARR38-C)
 * - Validates input pointer
 * - Strictly enforces maximum buffer capacity before copying
 * - Uses bounded memory copy (memcpy with explicit null-terminator)
 */

#define MAX_FILENAME_LEN 32

int parse_metadata(const char *input) {
    char filename[MAX_FILENAME_LEN];

    if (input == NULL) {
        fprintf(stderr, "Rejected: NULL input pointer\n");
        return 1;
    }

    size_t len = strlen(input);

    // Enforce bounds: strictly leave room for null terminator
    if (len >= sizeof(filename)) {
        printf("Rejected: metadata too long (length %u exceeds buffer size %u)\n", 
               (unsigned int)len, (unsigned int)(sizeof(filename) - 1));
        return 1;
    }

    memcpy(filename, input, len);
    filename[len] = '\0';

    printf("Processed safely: %s\n", filename);
    return 0;
}
