import os
import sys
import unittest
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as flask_app


class TestAppBaseline(unittest.TestCase):
    def setUp(self):
        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()
        self.rand_suffix = secrets.token_hex(4)

    def test_01_user_registration_and_login(self):
        username = f"user_{self.rand_suffix}"
        # Register user
        res = self.client.post("/register", data={"username": username, "password": "Password123!"})
        self.assertEqual(res.status_code, 302)

        # Logout (with valid CSRF token)
        with self.client.session_transaction() as sess:
            token = sess.get("csrf_token")
        res = self.client.post("/logout", data={"csrf_token": token})
        self.assertEqual(res.status_code, 302)

        # Login user
        res = self.client.post("/login", data={"username": username, "password": "Password123!"})
        self.assertEqual(res.status_code, 302)

    def test_02_duplicate_registration_rejected(self):
        username = f"dup_{self.rand_suffix}"
        # First registration
        res1 = self.client.post("/register", data={"username": username, "password": "Password123!"})
        self.assertEqual(res1.status_code, 302)

        # Duplicate registration attempt
        res2 = self.client.post("/register", data={"username": username, "password": "Password123!"})
        self.assertEqual(res2.status_code, 409)

    def test_03_file_upload_and_ownership(self):
        username = f"uploader_{self.rand_suffix}"
        self.client.post("/register", data={"username": username, "password": "Password123!"})

        with self.client.session_transaction() as sess:
            token = sess.get("csrf_token")

        upload_path = ROOT / "uploads" / "baseline_test.txt"
        upload_path.write_text("Security audit baseline data.")

        with open(upload_path, "rb") as f:
            res = self.client.post("/upload", data={
                "file": (f, "baseline_test.txt"),
                "csrf_token": token
            })
        self.assertEqual(res.status_code, 302)


if __name__ == "__main__":
    unittest.main()
