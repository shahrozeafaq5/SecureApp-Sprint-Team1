import sys
import re
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
PARSER_BIN = BASE_DIR / "native" / ("metadata_parser.exe" if sys.platform == "win32" else "metadata_parser")
if not PARSER_BIN.is_file():
    PARSER_BIN = BASE_DIR / "native" / "metadata_parser.exe"

FILENAME_PATTERN = r"[A-Za-z0-9_-]{1,64}\.txt"


def run_native_parser(target_string: str) -> bool:
    """Invokes the native C metadata parser with safe execve-style argument list."""
    if not PARSER_BIN.is_file():
        return True

    try:
        proc = subprocess.run(
            [str(PARSER_BIN), target_string],
            shell=False,
            capture_output=True,
            text=True,
            timeout=3
        )
        if proc.returncode != 0:
            print(f"[SECURITY ALERT] Native parser rejected metadata: {proc.stdout.strip() or proc.stderr.strip()}")
            return False
        return True
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"[SECURITY ALERT] Native parser execution error: {e}")
        return False


def main():
    if len(sys.argv) < 2:
        print("Error: Filename required")
        return 1

    saved_name = sys.argv[1]
    metadata_label = sys.argv[2] if len(sys.argv) > 2 else saved_name

    # Defense-in-depth: whitelist regex validation on saved_name
    if not re.fullmatch(FILENAME_PATTERN, saved_name):
        print("Error: Invalid saved filename pattern")
        return 1

    # Native C-level metadata parser execution on file metadata/original name
    if not run_native_parser(metadata_label):
        print("Error: Native C metadata validation failed (rejected)")
        return 1

    file_path = UPLOAD_DIR / saved_name

    if not file_path.is_file():
        print(f"Error: File '{saved_name}' not found")
        return 1

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        print(f"Processing '{metadata_label}' successful.")
        print("--- File Content ---")
        print(content)

        return 0

    except (OSError, UnicodeError):
        print("Error: Unable to read file")
        return 1


if __name__ == "__main__":
    sys.exit(main())
