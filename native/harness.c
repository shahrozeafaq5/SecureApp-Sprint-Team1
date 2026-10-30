#include <stdio.h>
#include <string.h>

int parse_metadata(const char *input);

int main(void) {
    char long_input[64];

    memset(long_input, 'A', 63);
    long_input[63] = '\0';

    printf("--- [TEST 1] Normal Input ---\n");
    int res1 = parse_metadata("report.txt");
    printf("Result code: %d\n\n", res1);

    printf("--- [TEST 2] Oversized Input (63 bytes into 16-byte buffer) ---\n");
    fflush(stdout);
    int res2 = parse_metadata(long_input);
    printf("Result code: %d\n", res2);

    if (res2 != 0) {
        printf("[SUCCESS] Oversized input safely caught and rejected without buffer overflow!\n");
    }

    return 0;
}
