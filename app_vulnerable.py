import os
import sys
import sqlite3
import subprocess
from pathlib import Path
from flask import (
    Flask, request, Response, render_template_string,
    redirect, url_for, session, send_from_directory
)

"""
DELIBERATELY VULNERABLE STARTER APPLICATION (LAB DEMONSTRATION ONLY)
CYC386 Midterm Lab Exam - DevSecOps Sprint Fall 2026

Vulnerabilities Exposed:
1. CWE-120/121: Buffer Overflow (via native C metadata parser)
2. CWE-78: OS Command Injection (via shell-interpolated execution)
3. CWE-639: Insecure Direct Object Reference (IDOR on download & delete)
4. CWE-352: Cross-Site Request Forgery (No CSRF tokens on state-changing actions)
5. CWE-1021: Clickjacking (Missing X-Frame-Options and frame-ancestors CSP)
"""

app = Flask(__name__)
app.secret_key = "insecure-hardcoded-secret-key-for-lab-demo"

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
DB_PATH = BASE_DIR / "secureapp_vuln.db"


def init_vuln_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()


init_vuln_db()

# NOTE: Deliberately NO @app.after_request applying X-Frame-Options or CSP (CWE-1021: Clickjacking)


@app.route("/")
def home():
    files = []
    username = session.get("username")
    if username:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        files = conn.execute("SELECT id, filename, owner_id FROM files").fetchall()
        conn.close()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable File Server (Pre-Remediation)</title></head>
    <body style="font-family:sans-serif; padding:20px;">
        <h1 style="color:#b91c1c;">Vulnerable File Server [PRE-REMEDIATION BASELINE]</h1>
        {% if session.get('username') %}
            <p>Logged in as: <b>{{ session['username'] }}</b> (ID: {{ session['user_id'] }})</p>
            <form action="/logout" method="POST"><button>Logout</button></form>
            <hr>
            <h3>Upload File (No CSRF, direct filename preservation)</h3>
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <input type="file" name="file" required>
                <button type="submit">Upload</button>
            </form>
            <hr>
            <h3>All Files (Notice IDOR exposure: All files displayed/accessible)</h3>
            <ul>
            {% for f in files %}
                <li>
                    ID {{ f['id'] }} - {{ f['filename'] }} (Owner ID: {{ f['owner_id'] }})
                    <a href="/download/{{ f['id'] }}">Download (IDOR)</a>
                    <form action="/process" method="POST" style="display:inline;">
                        <input type="hidden" name="filename" value="{{ f['filename'] }}">
                        <button type="submit">Process (Command Injection)</button>
                    </form>
                    <form action="/delete/{{ f['id'] }}" method="POST" style="display:inline;">
                        <button type="submit" style="color:red;">Delete (CSRF + IDOR)</button>
                    </form>
                </li>
            {% endfor %}
            </ul>
        {% else %}
            <h3>Login</h3>
            <form action="/login" method="POST">
                <input name="username" placeholder="Username" required>
                <input name="password" type="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <h3>Register</h3>
            <form action="/register" method="POST">
                <input name="username" placeholder="Username" required>
                <input name="password" type="password" placeholder="Password" required>
                <button type="submit">Register</button>
            </form>
        {% endif %}
    </body>
    </html>
    """, files=files)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO users(username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        session["user_id"] = cur.lastrowid
        session["username"] = username
    except Exception as e:
        return f"Registration error: {e}", 400
    finally:
        conn.close()
    return redirect(url_for("home"))


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    conn.close()
    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("home"))
    return "Invalid credentials", 401


@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# CWE-352: State-changing upload without CSRF token
@app.route("/upload", methods=["POST"])
def upload():
    if "user_id" not in session:
        return "Unauthorized", 401
    file = request.files.get("file")
    if file and file.filename:
        # Vulnerable: directly saves user-supplied filename without sanitization
        file.save(UPLOAD_DIR / file.filename)
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO files(owner_id, filename) VALUES (?, ?)", (session["user_id"], file.filename))
        conn.commit()
        conn.close()
    return redirect(url_for("home"))


# CWE-639: IDOR on file download - Only queries file ID, never checks owner_id!
@app.route("/download/<int:file_id>")
def download(file_id):
    if "user_id" not in session:
        return "Unauthorized", 401
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # VULNERABLE: Direct object reference without verifying ownership
    row = conn.execute("SELECT filename FROM files WHERE id = ?", (file_id,)).fetchone()
    conn.close()
    if not row:
        return "File not found", 404
    return send_from_directory(UPLOAD_DIR, row["filename"], as_attachment=True)


# CWE-639 & CWE-352: IDOR and CSRF on state-changing delete
@app.route("/delete/<int:file_id>", methods=["POST", "GET"])
def delete_file_vuln(file_id):
    if "user_id" not in session:
        return "Unauthorized", 401
    conn = sqlite3.connect(DB_PATH)
    # VULNERABLE: Deletes record purely based on URL parameter without checking owner_id or CSRF token!
    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("home"))


# CWE-78: Command Injection via shell=True and unsanitized filename input
@app.route("/process", methods=["POST"])
def process_file_vuln():
    if "user_id" not in session:
        return "Unauthorized", 401
    filename = request.form.get("filename", "")

    # Deliberately VULNERABLE: Direct shell command concatenation with user input
    cmd = f"{sys.executable} processor_vulnerable.py {filename}"
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return Response(f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}", mimetype="text/plain")
    except Exception as e:
        return f"Process failure: {e}", 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
