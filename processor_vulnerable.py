import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"


# CWE-78 Vulnerable Processor: Executes command via shell=True without parameterization or whitelisting
def main():
    if len(sys.argv) < 2:
        print("Error: Filename required")
        return 1

    user_input = sys.argv[1]

    # Deliberately VULNERABLE: Direct string interpolation into shell command (CWE-78)
    # Works across both Windows cmd.exe and Linux sh/bash
    cmd = f"echo Processing {user_input}"
    print(f"[VULNERABLE SHELL] Executing: {cmd}")

    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        print("--- Output ---")
        print(proc.stdout)
        if proc.stderr:
            print("--- Error ---")
            print(proc.stderr)
        return proc.returncode
    except Exception as e:
        print(f"Execution error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
