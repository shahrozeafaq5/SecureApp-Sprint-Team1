#include <stdio.h>
#include <string.h>

int parse_metadata(const char *input);

int main(void) {
    char long_input[64];

    memset(long_input, 'A', 63);
    long_input[63] = '\0';

    printf("Testing normal input...\n");
    parse_metadata("report.txt");

    printf("Testing oversized input...\n");
    fflush(stdout);
    parse_metadata(long_input);

    return 0;
}