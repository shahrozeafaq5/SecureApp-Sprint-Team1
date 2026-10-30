#include <stdio.h>
#include <string.h>

int parse_metadata(const char *input);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <metadata_string>\n", argv[0]);
        return 2;
    }

    return parse_metadata(argv[1]);
}
