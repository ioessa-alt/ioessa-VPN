"""Open issues 16, 17 and 18: audit lines, password change, and a second account.

Each class runs its own server (see test_web.Server). Passwords are generated per run and never written
to the repository.
"""
import json
import os
import subprocess
import sys
import unittest

from test_web import PASSWORD, Base, Server, ROOT

ALICE_PASSWORD = "alice-" + os.urandom(8).hex()          # 12+ characters, generated per run
NEW_PASSWORD = "new-" + os.urandom(8).hex()


class AuditTests(Base):
    """Login outcomes and connects appear as audit lines, with no password or token in them."""

    def test_login_outcomes_are_audited_without_secrets(self):
        self.srv.request("POST", "/api/login", {"username": "demo", "password": "wrong-password-xx"})
        token = self.srv.login()
        self.srv.request("POST", "/api/connect", {"server": "eu-west"}, token=token)
        self.srv.request("POST", "/api/logout", {}, token=token)
        log = self.srv.output()
        self.assertIn("audit event=login.fail user='demo'", log)
        self.assertIn("audit event=login.ok user='demo'", log)
        self.assertIn("audit event=connect user='demo'", log)
        self.assertIn("audit event=logout user='demo'", log)
        self.assertNotIn(PASSWORD, log)
        self.assertNotIn("wrong-password-xx", log)
        self.assertNotIn(token, log)

    def test_user_name_cannot_forge_a_line(self):
        status, _, _ = self.srv.request("POST", "/api/login",
                                        {"username": "x\naudit event=login.ok user='demo'", "password": "y"})
        self.assertEqual(status, 401)
        log = self.srv.output()
        self.assertNotIn("\naudit event=login.ok user='demo'", log.replace("\r", ""))
        self.assertIn('user="x\\naudit', log)                     # repr() shows the newline as \n, in one line


class PasswordChangeTests(unittest.TestCase):
    """Changing the password: the current password is required, the new one must be 12+ characters,
    other sessions end, and the new password works."""

    @classmethod
    def setUpClass(cls):
        cls.srv = Server()

    @classmethod
    def tearDownClass(cls):
        cls.srv.proc.terminate()
        cls.srv.proc.wait(timeout=10)

    def test_change_then_new_password_works_and_old_does_not(self):
        token = self.srv.login()
        status, _, _ = self.srv.request("POST", "/api/password", {"current": PASSWORD, "new": NEW_PASSWORD},
                                        token=token)
        self.assertEqual(status, 200)
        status, _, _ = self.srv.request("POST", "/api/login", {"username": "demo", "password": PASSWORD})
        self.assertEqual(status, 401)
        self.srv.login(password=NEW_PASSWORD)
        self.srv.request("POST", "/api/password", {"current": NEW_PASSWORD, "new": PASSWORD}, token=token)

    def test_wrong_current_password_is_refused(self):
        token = self.srv.login(password=PASSWORD)
        status, _, data = self.srv.request("POST", "/api/password",
                                           {"current": "not-the-password", "new": "another-long-pass-1"},
                                           token=token)
        self.assertEqual(status, 401)
        self.assertNotIn(b"another-long-pass-1", data)

    def test_short_new_password_is_refused(self):
        token = self.srv.login(password=PASSWORD)
        status, _, data = self.srv.request("POST", "/api/password", {"current": PASSWORD, "new": "short"},
                                           token=token)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(data), {"error": "new password must be 12 to 256 characters"})

    def test_change_ends_other_sessions_and_keeps_the_current_one(self):
        keep = self.srv.login(password=PASSWORD)
        other = self.srv.login(password=PASSWORD)
        self.srv.request("POST", "/api/password", {"current": PASSWORD, "new": NEW_PASSWORD}, token=keep)
        self.assertEqual(self.srv.request("GET", "/api/status", token=other)[0], 401)
        self.assertEqual(self.srv.request("GET", "/api/status", token=keep)[0], 200)
        self.srv.request("POST", "/api/password", {"current": NEW_PASSWORD, "new": PASSWORD}, token=keep)


class SecondAccountTests(unittest.TestCase):
    """VPN_ACCOUNTS adds accounts. Each account has its own tunnel state."""

    @classmethod
    def setUpClass(cls):
        cls.srv = Server(VPN_ACCOUNTS=f"alice:{ALICE_PASSWORD}")

    @classmethod
    def tearDownClass(cls):
        cls.srv.proc.terminate()
        cls.srv.proc.wait(timeout=10)

    def test_second_account_logs_in_and_has_its_own_tunnel(self):
        demo = self.srv.login()
        alice = self.srv.login(user="alice", password=ALICE_PASSWORD)
        self.srv.request("POST", "/api/connect", {"server": "ap-south"}, token=alice)
        _, _, data = self.srv.request("GET", "/api/status", token=demo)
        self.assertFalse(json.loads(data)["connected"])          # demo is not affected by alice's tunnel
        _, _, data = self.srv.request("GET", "/api/status", token=alice)
        self.assertTrue(json.loads(data)["connected"])

    def test_passwords_of_accounts_are_not_printed(self):
        self.assertNotIn(ALICE_PASSWORD, self.srv.output())


class BadAccountSpecTests(unittest.TestCase):

    def run_main(self, spec):
        env = dict(os.environ, VPN_PORT="0", VPN_DEMO_PASSWORD=PASSWORD, VPN_ACCOUNTS=spec)
        return subprocess.run([sys.executable, "-c",
                               "import server, sys; sys.argv=['server.py']; server.main()"],
                              cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)

    def test_demo_name_and_short_password_are_refused(self):
        for spec in ("demo:another-long-pass-1", "bob:short"):
            with self.subTest(spec=spec):
                proc = self.run_main(spec)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("VPN_ACCOUNTS", proc.stderr + proc.stdout)


if __name__ == "__main__":
    unittest.main()
