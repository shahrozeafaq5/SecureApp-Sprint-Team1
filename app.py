import os
import re
import sys
import sqlite3
import secrets
import subprocess
from pathlib import Path
from contextlib import contextmanager

from flask import (
    Flask, request, Response, render_template,
    redirect, url_for, session, send_from_directory, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Application Security Configuration
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB Max upload limit
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = False  # Set to True when served over HTTPS in production

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
DB_PATH = BASE_DIR / "secureapp.db"

FILENAME_PATTERN = r"[A-Za-z0-9_-]{1,64}\.txt"


@contextmanager
def database():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    finally:
        db.close()


def init_db():
    with database() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                saved_name TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            );
        """)


init_db()


# ---------------------------------------------------------
# Security Defense: Clickjacking & Hardened Response Headers
# CWE-1021: Improper Restriction of Rendered UI Layers
# ---------------------------------------------------------
@app.after_request
def apply_security_headers(response):
    # Clickjacking Mitigations: Block framing entirely
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    # MIME Sniffing Mitigation
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Legacy XSS Filter protection
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Referrer Leakage Mitigation
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ---------------------------------------------------------
# Security Defense: Cross-Site Request Forgery (CSRF)
# CWE-352: Cross-Site Request Forgery
# Synchronizer Token Pattern
# ---------------------------------------------------------
@app.before_request
def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


def validate_csrf():
    """Validates synchronizer anti-CSRF token on state-changing requests."""
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("csrf_token")
    if not token or not expected or not secrets.compare_digest(token, expected):
        return False
    return True


@app.route("/")
def home():
    files = []
    if "user_id" in session:
        with database() as db:
            files = db.execute(
                "SELECT id, original_name, saved_name FROM files WHERE owner_id = ?",
                (session["user_id"],)
            ).fetchall()
    return render_template("index.html", files=files, csrf_token=session.get("csrf_token"))


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return Response("Invalid username: must be 3-30 alphanumeric characters or underscore", status=400)

    if len(password) < 8:
        return Response("Password must have at least 8 characters", status=400)

    try:
        with database() as db:
            cursor = db.execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return Response("Username already exists", status=409)

    # Re-initialize clean session with fresh CSRF token
    session.clear()
    session["user_id"] = user_id
    session["username"] = username
    session["csrf_token"] = secrets.token_hex(32)
    return redirect(url_for("home"))


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with database() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return Response("Invalid credentials", status=401)

    # Session regeneration against session fixation
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["csrf_token"] = secrets.token_hex(32)
    return redirect(url_for("home"))


@app.route("/logout", methods=["POST"])
def logout():
    # Enforce CSRF protection on state-changing logout
    if not validate_csrf():
        return Response("403 Forbidden: CSRF token missing or invalid", status=403)

    session.clear()
    return redirect(url_for("home"))


@app.route("/upload", methods=["POST"])
def upload_file():
    if "user_id" not in session:
        return Response("Login required", status=401)

    # Enforce CSRF validation
    if not validate_csrf():
        return Response("403 Forbidden: CSRF token missing or invalid", status=403)

    file = request.files.get("file")
    if not file or not file.filename:
        return Response("No file selected", status=400)

    # Whitelist validation on uploaded filename
    if not re.fullmatch(FILENAME_PATTERN, file.filename):
        return Response("Rejected: invalid filename. Only alphanumeric characters and .txt allowed", status=400)

    # Random UUID-style storage filename prevents path traversal and collisions
    saved_name = secrets.token_hex(16) + ".txt"
    file_path = UPLOAD_DIR / saved_name
    file.save(file_path)

    with database() as db:
        db.execute(
            "INSERT INTO files(owner_id, original_name, saved_name) VALUES (?, ?, ?)",
            (session["user_id"], file.filename, saved_name)
        )

    return redirect(url_for("home"))


# ---------------------------------------------------------
# Security Defense: Command Injection & IDOR
# CWE-78: OS Command Injection
# CWE-639: Insecure Direct Object Reference (IDOR)
# ---------------------------------------------------------
@app.route("/process", methods=["POST"])
def process_file():
    if "user_id" not in session:
        return Response("Login required", status=401)

    # Enforce CSRF validation
    if not validate_csrf():
        return Response("403 Forbidden: CSRF token missing or invalid", status=403)

    try:
        file_id = int(request.form.get("file_id", ""))
    except ValueError:
        return Response("Invalid file ID", status=400)

    # IDOR Defense: Object-level authorization strictly checks file ownership
    with database() as db:
        record = db.execute(
            "SELECT original_name, saved_name FROM files WHERE id = ? AND owner_id = ?",
            (file_id, session["user_id"])
        ).fetchone()

    if not record:
        return Response("File not found or access denied (IDOR protection)", status=404)

    # Command Injection Defense:
    # 1. Parameterized execve argument array (NO shell=True)
    # 2. Strict input validation in processor.py
    # 3. Invocation of native C metadata parser with safe bounds
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(BASE_DIR / "processor.py"),
                record["saved_name"],
                record["original_name"]
            ],
            shell=False,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        return Response("Processing timed out", status=504)
    except OSError:
        return Response("Processing execution error", status=500)

    if result.returncode != 0:
        return Response(f"File processing rejected: {result.stdout or result.stderr}", status=400)

    return Response(result.stdout, mimetype="text/plain")


@app.route("/download/<int:file_id>")
def download_file(file_id):
    if "user_id" not in session:
        return Response("Login required", status=401)

    # IDOR Defense: Object-level authorization check
    with database() as db:
        record = db.execute(
            "SELECT original_name, saved_name FROM files WHERE id = ? AND owner_id = ?",
            (file_id, session["user_id"])
        ).fetchone()

    if not record:
        return Response("File not found or access denied (IDOR protection)", status=404)

    return send_from_directory(
        UPLOAD_DIR,
        record["saved_name"],
        as_attachment=True,
        download_name=record["original_name"]
    )


# ---------------------------------------------------------
# State-Changing Operation: File Deletion
# Demonstrates both IDOR & CSRF defense
# ---------------------------------------------------------
@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    if "user_id" not in session:
        return Response("Login required", status=401)

    # CSRF Defense
    if not validate_csrf():
        return Response("403 Forbidden: CSRF token missing or invalid", status=403)

    # IDOR Defense: Verifies ownership before deletion
    with database() as db:
        record = db.execute(
            "SELECT saved_name FROM files WHERE id = ? AND owner_id = ?",
            (file_id, session["user_id"])
        ).fetchone()

        if not record:
            return Response("File not found or access denied (IDOR protection)", status=404)

        # Remove from disk safely
        file_path = UPLOAD_DIR / record["saved_name"]
        if file_path.is_file():
            file_path.unlink()

        # Remove database record
        db.execute(
            "DELETE FROM files WHERE id = ? AND owner_id = ?",
            (file_id, session["user_id"])
        )

    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
