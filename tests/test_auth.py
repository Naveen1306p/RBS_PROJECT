import re
import smtplib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app


class AuthFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "WTF_CSRF_ENABLED": False,
                "SECRET_KEY": "test-key",
                "DATABASE": str(Path(self.temp_dir.name) / "test.sqlite3"),
                "ENVIRONMENT": "test",
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def signup(self, email="hello@example.com", password="correct-horse-battery"):
        return self.client.post(
            "/signup",
            data={
                "email": email,
                "password": password,
                "confirm_password": password,
            },
            follow_redirects=True,
        )

    def test_signup_signin_and_signout(self):
        response = self.signup()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"hello@example.com", response.data)

        self.client.post("/logout", follow_redirects=True)
        response = self.client.post(
            "/login",
            data={"email": "hello@example.com", "password": "correct-horse-battery"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"hello@example.com", response.data)

    def test_rejects_short_password(self):
        response = self.client.post(
            "/signup",
            data={"email": "short@example.com", "password": "short", "confirm_password": "short"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Field must be between 10 and 128 characters long.", response.data)

    def test_password_reset_link_is_one_time_and_updates_password(self):
        self.signup()
        with patch("app._send_reset_email") as send_email:
            response = self.client.post(
                "/forgot-password",
                data={"email": "hello@example.com"},
                follow_redirects=True,
            )
        self.assertEqual(response.status_code, 200)
        reset_url = send_email.call_args.args[1]
        token = re.search(r"/reset-password/([^/?]+)", reset_url).group(1)

        response = self.client.post(
            f"/reset-password/{token}",
            data={"password": "a-new-secure-password", "confirm_password": "a-new-secure-password"},
            follow_redirects=True,
        )
        self.assertIn(b"Your password has been updated.", response.data)
        self.client.post("/logout", follow_redirects=True)
        response = self.client.post(
            "/login",
            data={"email": "hello@example.com", "password": "a-new-secure-password"},
            follow_redirects=True,
        )
        self.assertIn(b"hello@example.com", response.data)

        response = self.client.get(f"/reset-password/{token}", follow_redirects=True)
        self.assertIn(b"invalid or has expired", response.data)

    def test_unknown_email_gets_same_reset_response(self):
        self.signup()
        with patch("app._send_reset_email", side_effect=smtplib.SMTPException("mail unavailable")):
            known = self.client.post(
                "/forgot-password",
                data={"email": "hello@example.com"},
                follow_redirects=True,
            )
        unknown = self.client.post(
            "/forgot-password",
            data={"email": "missing@example.com"},
            follow_redirects=True,
        )
        self.assertIn(b"If an account exists for that email", known.data)
        self.assertEqual(known.data, unknown.data)

    def test_signup_requires_csrf_token(self):
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "csrf-test-key",
                "DATABASE": str(Path(self.temp_dir.name) / "csrf.sqlite3"),
                "ENVIRONMENT": "test",
                "WTF_CSRF_ENABLED": True,
            }
        )
        client = app.test_client()
        client.get("/signup")
        response = client.post(
            "/signup",
            data={
                "email": "csrf@example.com",
                "password": "correct-horse-battery",
                "confirm_password": "correct-horse-battery",
            },
        )
        self.assertIn(b"The CSRF token is missing.", response.data)


if __name__ == "__main__":
    unittest.main()
