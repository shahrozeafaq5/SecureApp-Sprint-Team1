import os
import sys
import unittest
import tempfile
import sqlite3
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as flask_app

class TestAppBaseline(unittest.TestCase):
    def setUp(self):
        flask_app.app.config["TESTING"] = True
        flask_app.app.config["SECRET_KEY"] = "test-secret-key-12345"
        self.client = flask_app.app.test_client()

    def test_01_user_registration_and_login(self):
        # Register user1
        res = self.client.post("/register", data={"username": "alice", "password": "Password123!"})
        self.assertEqual(res.status_code, 302)

        # Logout
        res = self.client.post("/logout")
        self.assertEqual(res.status_code, 302)

        # Login user1
        res = self.client.post("/login", data={"username": "alice", "password": "Password123!"})
        self.assertEqual(res.status_code, 302)

    def test_02_duplicate_registration_rejected(self):
        # Trying to register existing username
        res = self.client.post("/register", data={"username": "alice", "password": "Password123!"})
        self.assertEqual(res.status_code, 409)

    def test_03_file_upload_and_ownership(self):
        # Login alice
        self.client.post("/login", data={"username": "alice", "password": "Password123!"})

        # Upload file
        data = {
            "file": (tempfile.NamedTemporaryFile(suffix=".txt", delete=False), "report.txt")
        }
        with open("report.txt", "w") as f:
            f.write("Security audit baseline data.")

        with open("report.txt", "rb") as f:
            res = self.client.post("/upload", data={"file": (f, "report.txt")})
        self.assertEqual(res.status_code, 302)

if __name__ == "__main__":
    unittest.main()
