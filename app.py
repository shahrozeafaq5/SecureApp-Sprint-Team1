
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
    redirect, url_for, session, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

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
                password_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                saved_name TEXT UNIQUE NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            );
        """)


init_db()


@app.route("/")
def home():
    files = []
    if "user_id" in session:
        with database() as db:
            files = db.execute(
                "SELECT id, original_name FROM files WHERE owner_id = ?",
                (session["user_id"],)
            ).fetchall()
    return render_template("index.html", files=files)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return Response("Invalid username", status=400)

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

    session.clear()
    session["user_id"] = user_id
    session["username"] = username
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

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(url_for("home"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/upload", methods=["POST"])
def upload_file():
    if "user_id" not in session:
        return Response("Login required", status=401)

    file = request.files.get("file")

    if not file or not file.filename:
        return Response("No file selected", status=400)

    if not re.fullmatch(FILENAME_PATTERN, file.filename):
        return Response("Rejected: invalid filename", status=400)

    saved_name = secrets.token_hex(16) + ".txt"
    file.save(UPLOAD_DIR / saved_name)

    with database() as db:
        db.execute(
            "INSERT INTO files(owner_id, original_name, saved_name) VALUES (?, ?, ?)",
            (session["user_id"], file.filename, saved_name)
        )

    return redirect(url_for("home"))


@app.route("/process", methods=["POST"])
def process_file():
    if "user_id" not in session:
        return Response("Login required", status=401)

    try:
        file_id = int(request.form.get("file_id", ""))
    except ValueError:
        return Response("Invalid file ID", status=400)

    with database() as db:
        record = db.execute(
            "SELECT saved_name FROM files WHERE id = ? AND owner_id = ?",
            (file_id, session["user_id"])
        ).fetchone()

    if not record:
        return Response("File not found or access denied", status=404)

    try:
        result = subprocess.run(
            [sys.executable, str(BASE_DIR / "processor.py"), record["saved_name"]],
            shell=False,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        return Response("Processing timed out", status=504)
    except OSError:
        return Response("Processing error", status=500)

    if result.returncode != 0:
        return Response("File processing failed", status=500)

    return Response(result.stdout, mimetype="text/plain")


@app.route("/download/<int:file_id>")
def download_file(file_id):
    if "user_id" not in session:
        return Response("Login required", status=401)

    with database() as db:
        record = db.execute(
            "SELECT original_name, saved_name FROM files WHERE id = ? AND owner_id = ?",
            (file_id, session["user_id"])
        ).fetchone()

    if not record:
        return Response("File not found or access denied", status=404)

    return send_from_directory(
        UPLOAD_DIR,
        record["saved_name"],
        as_attachment=True,
        download_name=record["original_name"]
    )


if __name__ == "__main__":
    app.run(debug=False)
