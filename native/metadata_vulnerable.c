#include <stdio.h>
#include <string.h>

/*
 * Deliberately Vulnerable Metadata Parser (Lab Demonstration Only)
 * CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
 * CWE-121: Stack-based Buffer Overflow
 */
int parse_metadata(const char *input) {
    char filename[32];

    // VULNERABLE: No length validation. Copying unbounded input into fixed-size stack buffer.
    size_t len = strlen(input);

    for (size_t i = 0; i <= len; i++) {
        filename[i] = input[i];
    }

    printf("Processed: %s\n", filename);
    return 0;
}
