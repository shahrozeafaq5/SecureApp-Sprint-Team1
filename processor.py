
import sys
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"

FILENAME_PATTERN = r"[A-Za-z0-9_-]{1,64}\.txt"


def main():
    if len(sys.argv) != 2:
        print("Error: Filename required")
        return 1

    filename = sys.argv[1]

    if not re.fullmatch(FILENAME_PATTERN, filename):
        print("Error: Invalid filename")
        return 1

    file_path = UPLOAD_DIR / filename

    if not file_path.is_file():
        print(f"Error: File '{filename}' not found")
        return 1

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        print(f"Processing '{filename}' successful.")
        print("--- File Content ---")
        print(content)

        return 0

    except (OSError, UnicodeError):
        print("Error: Unable to read file")
        return 1


if __name__ == "__main__":
    sys.exit(main())
