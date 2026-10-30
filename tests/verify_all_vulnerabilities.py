"""
Automated Verification & Proof-of-Concept Test Harness
CYC386 Secure Software Design and Development - Fall 2026
Team Members:
- Talal Nadeem Awan (FA23-BCT-051)
- Shahroze Afaq (FA23-BCT-039)

This test suite executes and verifies all 5 mandatory vulnerability classes:
1. Buffer Overflow (CWE-120 / CWE-121)
2. OS Command Injection (CWE-78)
3. Insecure Direct Object Reference (CWE-639)
4. Cross-Site Request Forgery (CWE-352)
5. Clickjacking / UI Redressing (CWE-1021)
"""

import os
import sys
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as secure_app
import app_vulnerable as vuln_app


class TestVulnerabilityProof(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Configure test clients
        secure_app.app.config["TESTING"] = True
        cls.sec_client = secure_app.app.test_client()

        vuln_app.app.config["TESTING"] = True
        cls.vuln_client = vuln_app.app.test_client()

    # -------------------------------------------------------------
    # 1. BUFFER OVERFLOW (CWE-120 / CWE-121)
    # -------------------------------------------------------------
    def test_01_buffer_overflow_before_after(self):
        print("\n=======================================================")
        print(" [TEST 1] CWE-120 / CWE-121: BUFFER OVERFLOW")
        print("=======================================================")

        # Vulnerable binary test (should abort due to stack canary / crash)
        vuln_bin = ROOT / "parser_vulnerable.exe"
        if not vuln_bin.is_file():
            vuln_bin = ROOT / "parser_vulnerable"
        if vuln_bin.is_file():
            if sys.platform != "win32":
                os.chmod(str(vuln_bin), 0o755)
            res_vuln = subprocess.run([str(vuln_bin)], capture_output=True, text=True)
            print(f"[-] Vulnerable parser exit code: {res_vuln.returncode}")
            print(f"[-] Output preview:\n{res_vuln.stdout[:200]}")
            self.assertNotEqual(res_vuln.returncode, 0, "Vulnerable parser must fail on oversized input")
            print("[+] CONFIRMED: Vulnerable parser triggers memory corruption / stack smashing!")

        # Secure binary test (must catch bounds without crashing)
        sec_bin = ROOT / "parser_secure.exe"
        if not sec_bin.is_file():
            sec_bin = ROOT / "parser_secure"
        if sec_bin.is_file():
            if sys.platform != "win32":
                os.chmod(str(sec_bin), 0o755)
            res_sec = subprocess.run([str(sec_bin)], capture_output=True, text=True)
            print(f"[+] Secure parser exit code: {res_sec.returncode}")
            print(f"[+] Secure parser output:\n{res_sec.stdout}")
            self.assertEqual(res_sec.returncode, 0, "Secure harness must execute gracefully")
            self.assertIn("Rejected: metadata too long", res_sec.stdout)
            self.assertIn("[SUCCESS] Oversized input safely caught", res_sec.stdout)
            print("[+] CONFIRMED: Secure parser enforces strict bounds and prevents buffer overflow!")

    # -------------------------------------------------------------
    # 2. OS COMMAND INJECTION (CWE-78)
    # -------------------------------------------------------------
    def test_02_command_injection_before_after(self):
        print("\n=======================================================")
        print(" [TEST 2] CWE-78: OS COMMAND INJECTION")
        print("=======================================================")

        # Attack payload designed to execute an arbitrary command
        payload = "report.txt & echo LAB_MARKER"

        # BEFORE: Vulnerable execution via shell=True inside processor_vulnerable.py
        res_vuln = subprocess.run(
            [sys.executable, str(ROOT / "processor_vulnerable.py"), payload],
            shell=False,
            capture_output=True,
            text=True
        )
        print(f"[-] Vulnerable processor output:\n{res_vuln.stdout}")
        self.assertIn("LAB_MARKER", res_vuln.stdout, "Vulnerable processor must execute injected shell command")
        print("[+] CONFIRMED: Command Injection succeeds on vulnerable component (LAB_MARKER executed)!")

        # AFTER: Secure execution via safe argument array and whitelist
        res_sec = subprocess.run(
            [sys.executable, str(ROOT / "processor.py"), payload],
            shell=False,
            capture_output=True,
            text=True
        )
        print(f"[+] Secure processor output:\n{res_sec.stdout}")
        self.assertNotIn("LAB_MARKER", res_sec.stdout)
        self.assertIn("Error: Invalid saved filename pattern", res_sec.stdout)
        self.assertNotEqual(res_sec.returncode, 0)
        print("[+] CONFIRMED: Command Injection safely blocked by regex allowlist and parameterized subprocess!")

    # -------------------------------------------------------------
    # 3. INSECURE DIRECT OBJECT REFERENCE - IDOR (CWE-639)
    # -------------------------------------------------------------
    def test_03_idor_before_after(self):
        print("\n=======================================================")
        print(" [TEST 3] CWE-639: INSECURE DIRECT OBJECT REFERENCE (IDOR)")
        print("=======================================================")

        # Register User 1 (Alice)
        self.sec_client.post("/register", data={"username": "alice_sec_poc", "password": "Password123!"})
        alice_file_path = ROOT / "uploads" / "alice_confidential.txt"
        alice_file_path.write_text("CONFIDENTIAL_ALICE_DATA_TOP_SECRET")

        with secure_app.database() as db:
            db.execute("DELETE FROM files WHERE id = 101")
            db.execute(
                "INSERT INTO files (id, owner_id, original_name, saved_name) VALUES (101, 1, 'alice_confidential.txt', 'alice_confidential.txt')"
            )

        # Log in as Bob (User 2 - ID 999)
        with self.sec_client.session_transaction() as sess:
            sess["user_id"] = 999
            sess["username"] = "bob_sec"

        # Bob attempts to download Alice's file (File ID 101, owner_id 1) in secure app
        res_sec = self.sec_client.get("/download/101")
        print(f"[+] Secure App response code to Bob accessing Alice's file: {res_sec.status_code}")
        self.assertEqual(res_sec.status_code, 404, "Secure app must deny unauthorized object access")
        res_sec.close()
        print("[+] CONFIRMED: IDOR attempt rejected with HTTP 404/Access Denied!")

        # IN VULNERABLE APP:
        conn = vuln_app.sqlite3.connect(vuln_app.DB_PATH)
        conn.execute("INSERT OR REPLACE INTO users(id, username, password) VALUES (1, 'alice_vuln', 'pass1')")
        conn.execute("INSERT OR REPLACE INTO users(id, username, password) VALUES (2, 'bob_vuln', 'pass2')")
        conn.execute("INSERT OR REPLACE INTO files(id, owner_id, filename) VALUES (1, 1, 'alice_confidential.txt')")
        conn.commit()
        conn.close()

        # Bob logs into vulnerable app
        with self.vuln_client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "bob_vuln"

        # Bob attempts to download Alice's file in vulnerable app
        res_vuln = self.vuln_client.get("/download/1")
        print(f"[-] Vulnerable App response code to Bob accessing Alice's file: {res_vuln.status_code}")
        self.assertEqual(res_vuln.status_code, 200, "Vulnerable app permits unauthorized access")
        self.assertIn(b"CONFIDENTIAL_ALICE_DATA", res_vuln.data)
        res_vuln.close()
        print("[+] CONFIRMED: IDOR succeeds on pre-remediation app (Bob accessed Alice's private file)!")

    # -------------------------------------------------------------
    # 4. CROSS-SITE REQUEST FORGERY - CSRF (CWE-352)
    # -------------------------------------------------------------
    def test_04_csrf_before_after(self):
        print("\n=======================================================")
        print(" [TEST 4] CWE-352: CROSS-SITE REQUEST FORGERY (CSRF)")
        print("=======================================================")

        # In Vulnerable App: Attacker triggers state-changing delete without CSRF token
        with self.vuln_client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "victim_user"

        res_vuln = self.vuln_client.post("/delete/1")
        print(f"[-] Vulnerable App response to forged request without token: {res_vuln.status_code}")
        self.assertEqual(res_vuln.status_code, 302, "Vulnerable app processes state change without anti-CSRF token")
        print("[+] CONFIRMED: CSRF attack succeeds on vulnerable endpoint!")

        # In Secure App: Attacker attempts forged POST without valid CSRF token
        with self.sec_client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "victim_user"
            sess["csrf_token"] = "legitimate_session_token_xyz"

        # POST without csrf_token form field
        res_sec = self.sec_client.post("/delete/1", data={})
        print(f"[+] Secure App response to forged request without token: {res_sec.status_code}")
        self.assertEqual(res_sec.status_code, 403, "Secure app must strictly reject forged request")
        self.assertIn(b"CSRF token missing or invalid", res_sec.data)
        print("[+] CONFIRMED: CSRF attack blocked with HTTP 403 Forbidden!")

    # -------------------------------------------------------------
    # 5. CLICKJACKING / UI REDRESSING (CWE-1021)
    # -------------------------------------------------------------
    def test_05_clickjacking_headers_before_after(self):
        print("\n=======================================================")
        print(" [TEST 5] CWE-1021: CLICKJACKING & UI REDRESSING")
        print("=======================================================")

        # Vulnerable app headers
        res_vuln = self.vuln_client.get("/")
        print(f"[-] Vulnerable App X-Frame-Options: {res_vuln.headers.get('X-Frame-Options')}")
        print(f"[-] Vulnerable App CSP: {res_vuln.headers.get('Content-Security-Policy')}")
        self.assertIsNone(res_vuln.headers.get("X-Frame-Options"))
        self.assertIsNone(res_vuln.headers.get("Content-Security-Policy"))
        print("[+] CONFIRMED: Vulnerable app lacks anti-framing headers (Framing Permitted)!")

        # Secure app headers
        res_sec = self.sec_client.get("/")
        print(f"[+] Secure App X-Frame-Options: {res_sec.headers.get('X-Frame-Options')}")
        print(f"[+] Secure App CSP: {res_sec.headers.get('Content-Security-Policy')}")
        self.assertEqual(res_sec.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", res_sec.headers.get("Content-Security-Policy", ""))
        print("[+] CONFIRMED: Secure app strictly blocks framing via X-Frame-Options and CSP frame-ancestors!")


if __name__ == "__main__":
    unittest.main()
