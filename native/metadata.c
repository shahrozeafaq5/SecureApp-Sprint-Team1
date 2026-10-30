#include <stdio.h>
#include <string.h>

int parse_metadata(const char *input) {
    char filename[16];

    // Vulnerable: no length validation
    size_t len = strlen(input);

    for (size_t i = 0; i <= len; i++) {
        filename[i] = input[i];
    }

    printf("Processed: %s\n", filename);
    return 0;
}