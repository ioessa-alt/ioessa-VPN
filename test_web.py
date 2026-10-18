"""HTTP tests for the mock VPN controller (server.py).

Run from the project root:  python -m unittest test_web

Each group starts its own server process on a free port, with a fixed demo
password and short lockout/session timers where a test needs them. Standard
library only.
"""
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PASSWORD = "test-pass-for-unit-tests-1"
LOGIN_FAILED = {"error": "invalid credentials or too many attempts, try again later"}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """A server.py process on its own port, with stdout captured to a file."""

    def __init__(self, password=PASSWORD, **env):
        self.port = free_port()
        self.log = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
        self.log.close()
        e = dict(os.environ, PYTHONUNBUFFERED="1", VPN_PORT=str(self.port))
        if password is not None:
            e["VPN_DEMO_PASSWORD"] = password
        e.update({k: str(v) for k, v in env.items()})
        with open(self.log.name, "w") as out:
            self.proc = subprocess.Popen(
                [sys.executable, "server.py"], cwd=str(ROOT), env=e,
                stdout=out, stderr=subprocess.STDOUT,
            )
        self._wait_ready()

    def _wait_ready(self):
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("server exited: " + self.output())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("server did not start")

    def output(self):
        with open(self.log.name) as f:
            return f.read()

    def request(self, method, path, body=None, token=None, headers=None, host=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        if token:
            h["Authorization"] = "Bearer " + token
        if body is not None:
            h["Content-Type"] = "application/json"
            raw = json.dumps(body).encode()
        if host is not None:
            h["Host"] = host
        conn.request(method, path, body=raw, headers=h)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res.status, {k.lower(): v for k, v in res.getheaders()}, data

    def login(self, user="demo", password=PASSWORD):
        status, _, data = self.request("POST", "/api/login", {"username": user, "password": password})
        if status != 200:
            raise AssertionError(f"login failed: {status} {data!r}")
        return json.loads(data)["token"]

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        try:
            os.unlink(self.log.name)
        except OSError:
            pass


class Base(unittest.TestCase):
    """Shares one server per class, started in setUpClass."""
    env = {}
    password = PASSWORD

    @classmethod
    def setUpClass(cls):
        cls.srv = Server(password=cls.password, **cls.env)

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()


class HeadersAndUI(Base):
    # Keep demo failures in this server low; successful logins reset the count.

    def test_ui_has_no_inline_script_and_csp_allows_only_self(self):
        status, h, body = self.srv.request("GET", "/")
        self.assertEqual(status, 200)
        html = body.decode()
        self.assertIsNone(re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline <script> found")
        self.assertIn('<script src="/app.js">', html)
        self.assertIn('<link rel="stylesheet" href="/app.css">', html)
        csp = h["content-security-policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertIn("base-uri 'none'", csp)
        self.assertIn("form-action 'self'", csp)

    def test_static_files_served_and_nothing_else(self):
        status, h, body = self.srv.request("GET", "/app.js")
        self.assertEqual(status, 200)
        self.assertTrue(h["content-type"].startswith("application/javascript"))
        self.assertIn(b"loginForm", body)
        status, h, _ = self.srv.request("GET", "/app.css")
        self.assertEqual(status, 200)
        self.assertTrue(h["content-type"].startswith("text/css"))
        # Only whitelisted files are readable; server source is not.
        status, _, body = self.srv.request("GET", "/server.py")
        self.assertEqual(status, 401)
        self.assertNotIn(b"import hashlib", body)

    def test_security_headers_on_page_and_api(self):
        for path in ("/", "/api/servers"):
            _, h, _ = self.srv.request("GET", path)
            self.assertEqual(h["x-content-type-options"], "nosniff", path)
            self.assertEqual(h["x-frame-options"], "DENY", path)
            self.assertEqual(h["referrer-policy"], "no-referrer", path)
            self.assertEqual(h["cache-control"], "no-store", path)
            self.assertIn("frame-ancestors 'none'", h["content-security-policy"], path)

    def test_ui_script_uses_no_dangerous_dom_sinks(self):
        # Static guard: server data must reach the DOM via textContent or
        # createElement, never through HTML parsing or script evaluation.
        _, _, body = self.srv.request("GET", "/app.js")
        js = body.decode()
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                     "eval(", "new Function", "setTimeout(\"", "location.hash", "location.search"):
                self.assertNotIn(sink, js, sink)

    def test_server_header_hides_python_version(self):
        _, h, _ = self.srv.request("GET", "/")
        self.assertEqual(h["server"], "MockVPN")

    def test_host_header_must_be_loopback(self):
        status, _, body = self.srv.request("GET", "/", host=f"evil.example:{self.srv.port}")
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden"})
        status, _, _ = self.srv.request("POST", "/api/login", {"username": "x", "password": "y"},
                                        host="attacker.test")
        self.assertEqual(status, 403)
        status, _, _ = self.srv.request("GET", "/", host=f"localhost:{self.srv.port}")
        self.assertEqual(status, 200)

    def test_unsupported_methods_get_json_errors(self):
        for method, path in (("HEAD", "/"), ("OPTIONS", "/api/login"), ("PUT", "/api/status")):
            status, h, body = self.srv.request(method, path)
            self.assertEqual(status, 501, method)
            self.assertTrue(h["content-type"].startswith("application/json"), method)
            self.assertNotIn(b"Python", body)
            self.assertNotIn(b"<html", body.lower())


class AuthAndInput(Base):

    def test_every_api_route_requires_a_session(self):
        routes = [("GET", "/api/servers"), ("GET", "/api/status"), ("POST", "/api/connect"),
                  ("POST", "/api/disconnect"), ("POST", "/api/logout"), ("GET", "/api/unknown")]
        for method, path in routes:
            for token in (None, "bogus-token"):
                body = {"server": "eu-west"} if path == "/api/connect" else None
                status, _, data = self.srv.request(method, path, body=body, token=token)
                self.assertEqual(status, 401, f"{method} {path} token={token}")
                self.assertEqual(json.loads(data), {"error": "not authenticated"})

    def test_login_token_is_long_random_and_unique(self):
        tokens = [self.srv.login() for _ in range(2)]
        self.assertNotEqual(tokens[0], tokens[1])
        for t in tokens:
            self.assertGreaterEqual(len(t), 43)  # 32 random bytes, base64url
            self.assertRegex(t, r"^[A-Za-z0-9_-]+$")
        status, _, _ = self.srv.request("GET", "/api/servers", token=tokens[0])
        self.assertEqual(status, 200)

    def test_logout_invalidates_token_on_server(self):
        token = self.srv.login()
        status, _, _ = self.srv.request("POST", "/api/logout", {}, token=token)
        self.assertEqual(status, 200)
        status, _, _ = self.srv.request("GET", "/api/status", token=token)
        self.assertEqual(status, 401)

    def test_unknown_user_and_wrong_password_look_identical(self):
        s1, _, b1 = self.srv.request("POST", "/api/login", {"username": "nobody-here", "password": "x"})
        s2, _, b2 = self.srv.request("POST", "/api/login", {"username": "demo", "password": "wrong"})
        self.assertEqual((s1, b1), (401, json.dumps(LOGIN_FAILED).encode()))
        self.assertEqual((s2, b2), (401, json.dumps(LOGIN_FAILED).encode()))

    def test_malformed_credentials_get_the_same_answer(self):
        cases = [
            {"username": 5, "password": PASSWORD},
            {"username": "demo", "password": ["x"]},
            {"username": "a" * 65, "password": PASSWORD},
            {"username": "demo", "password": "p" * 257},
            {"password": PASSWORD},
        ]
        for body in cases:
            status, _, data = self.srv.request("POST", "/api/login", body)
            self.assertEqual(status, 401, body.keys())
            self.assertEqual(json.loads(data), LOGIN_FAILED)

    def test_login_requires_json_content_type(self):
        for ctype in ("text/plain", "application/x-www-form-urlencoded"):
            status, _, data = self.srv.request(
                "POST", "/api/login", raw=json.dumps({"username": "demo", "password": PASSWORD}).encode(),
                headers={"Content-Type": ctype})
            self.assertEqual(status, 415, ctype)
            self.assertNotIn(b"token", data)
        status, _, _ = self.srv.request("POST", "/api/login", {"username": "demo", "password": PASSWORD})
        self.assertEqual(status, 200)

    def test_oversized_body_rejected_without_reading_it(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=10)
        conn.putrequest("POST", "/api/login")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "5000")
        conn.endheaders()  # no body sent; the limit must be checked from the header
        res = conn.getresponse()
        self.assertEqual(res.status, 400)
        conn.close()

    def test_invalid_json_and_non_object_are_400(self):
        status, _, data = self.srv.request("POST", "/api/login", raw=b"{not json",
                                           headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(data), {"error": "bad request"})
        status, _, _ = self.srv.request("POST", "/api/login", raw=b"[1, 2]",
                                        headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)

    def test_error_bodies_contain_no_traces(self):
        for body in (b"{not json", b"[]"):
            status, _, data = self.srv.request("POST", "/api/login", raw=body,
                                               headers={"Content-Type": "application/json"})
            self.assertEqual(status, 400)
            self.assertNotIn(b"Traceback", data)
            self.assertNotIn(b".py", data)


class TunnelState(Base):

    def test_connect_status_disconnect_flow(self):
        token = self.srv.login()
        status, _, data = self.srv.request("GET", "/api/servers", token=token)
        self.assertEqual({s["id"] for s in json.loads(data)}, {"eu-west", "us-east", "ap-south"})
        status, _, data = self.srv.request("POST", "/api/connect", {"server": "eu-west"}, token=token)
        self.assertEqual(status, 200)
        st = json.loads(data)
        self.assertTrue(st["connected"])
        self.assertTrue(st["vip"].startswith("10.8.0."))
        status, _, data = self.srv.request("POST", "/api/disconnect", {}, token=token)
        self.assertFalse(json.loads(data)["connected"])

    def test_connect_rejects_unknown_server(self):
        token = self.srv.login()
        for body in ({"server": "mars"}, {"server": 5}, {}):
            status, _, data = self.srv.request("POST", "/api/connect", body, token=token)
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(data), {"error": "unknown server"})

    def test_logout_drops_tunnel(self):
        token = self.srv.login()
        self.srv.request("POST", "/api/connect", {"server": "us-east"}, token=token)
        self.srv.request("POST", "/api/logout", {}, token=token)
        token2 = self.srv.login()
        _, _, data = self.srv.request("GET", "/api/status", token=token2)
        self.assertFalse(json.loads(data)["connected"])


class Lockout(Base):
    env = {"VPN_LOCKOUT_SECONDS": "2"}

    def _fail(self, n):
        for _ in range(n):
            status, _, _ = self.srv.request("POST", "/api/login", {"username": "demo", "password": "wrong"})
            self.assertEqual(status, 401)

    def test_lockout_answer_matches_a_wrong_password(self):
        self._fail(5)  # the fifth failure locks the account
        status, _, data = self.srv.request("POST", "/api/login", {"username": "demo", "password": PASSWORD})
        self.assertEqual(status, 401)  # the correct password is refused while locked
        self.assertEqual(json.loads(data), LOGIN_FAILED)
        status, _, data = self.srv.request("POST", "/api/login", {"username": "ghost", "password": "x"})
        self.assertEqual((status, json.loads(data)), (401, LOGIN_FAILED))

    def test_lockout_expires_and_counter_resets(self):
        self._fail(5)
        time.sleep(2.5)  # LOCKOUT is 2 seconds in this server
        token = self.srv.login()  # correct password works again
        self.assertTrue(token)
        self._fail(1)  # one failure after a reset must not re-lock
        self.srv.login()

    def test_unknown_names_are_never_locked_and_do_not_grow_state(self):
        for i in range(12):
            status, _, _ = self.srv.request("POST", "/api/login",
                                            {"username": f"name{i}", "password": "x"})
            self.assertEqual(status, 401)
        self.srv.login()  # the real account is unaffected by other names


class ConcurrentLockout(Base):
    # A long lock, so the batch cannot outlive it while it runs.
    env = {"VPN_LOCKOUT_SECONDS": "60"}

    def test_concurrent_wrong_passwords_still_lock_the_account(self):
        """Race check: the count is taken under LOCK, so parallel guesses cannot run past MAX_FAILS.
        The correct password must be refused once the batch is over."""
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(
                lambda _: self.srv.request("POST", "/api/login", {"username": "demo", "password": "wrong"})[0],
                range(16)))
        self.assertEqual(set(results), {401})
        status, _, _ = self.srv.request("POST", "/api/login", {"username": "demo", "password": PASSWORD})
        self.assertEqual(status, 401)
        time.sleep(2.5)  # let this lock expire so the next test starts from a clean count


class SessionExpiry(Base):
    env = {"VPN_SESSION_TTL": "2"}

    def test_session_expires_after_ttl(self):
        token = self.srv.login()
        status, _, _ = self.srv.request("GET", "/api/status", token=token)
        self.assertEqual(status, 200)
        time.sleep(2.5)
        status, _, _ = self.srv.request("GET", "/api/status", token=token)
        self.assertEqual(status, 401)

    def test_expired_session_takes_its_tunnel_with_it(self):
        token = self.srv.login()
        self.srv.request("POST", "/api/connect", {"server": "ap-south"}, token=token)
        time.sleep(2.5)
        token2 = self.srv.login()  # login prunes expired sessions and their tunnels
        _, _, data = self.srv.request("GET", "/api/status", token=token2)
        self.assertFalse(json.loads(data)["connected"])


class SessionIdle(Base):
    env = {"VPN_SESSION_IDLE": "1", "VPN_SESSION_TTL": "600"}

    def test_idle_session_is_refused(self):
        token = self.srv.login()
        time.sleep(1.5)  # no requests for longer than VPN_SESSION_IDLE
        status, _, _ = self.srv.request("GET", "/api/status", token=token)
        self.assertEqual(status, 401)

    def test_activity_keeps_a_session_alive(self):
        token = self.srv.login()
        for _ in range(6):  # about 1.5 s of activity, every 0.25 s, with a 1 s idle limit
            time.sleep(0.25)
            status, _, _ = self.srv.request("GET", "/api/status", token=token)
            self.assertEqual(status, 200)


class SessionLimit(Base):
    env = {"VPN_MAX_SESSIONS": "2"}

    def test_oldest_session_is_evicted_at_the_limit(self):
        t1 = self.srv.login()
        t2 = self.srv.login()
        t3 = self.srv.login()  # the third login evicts the least recently used, t1
        self.assertEqual(self.srv.request("GET", "/api/status", token=t1)[0], 401)
        self.assertEqual(self.srv.request("GET", "/api/status", token=t2)[0], 200)
        self.assertEqual(self.srv.request("GET", "/api/status", token=t3)[0], 200)

    def test_recent_use_protects_a_session_from_eviction(self):
        t1 = self.srv.login()
        t2 = self.srv.login()
        self.srv.request("GET", "/api/status", token=t1)  # t1 is now the most recently used
        self.srv.login()  # evicts t2
        self.assertEqual(self.srv.request("GET", "/api/status", token=t2)[0], 401)
        self.assertEqual(self.srv.request("GET", "/api/status", token=t1)[0], 200)


class SessionTunnelOwnership(Base):
    """The tunnel belongs to the user. Eviction of one session keeps it while another session of
    the same user is live. An explicit logout always ends it."""
    env = {"VPN_MAX_SESSIONS": "2"}

    def test_eviction_keeps_the_tunnel_for_the_remaining_session(self):
        t1 = self.srv.login()
        t2 = self.srv.login()
        self.srv.request("POST", "/api/connect", {"server": "eu-west"}, token=t2)
        self.srv.login()  # evicts t1; t2 is still live
        self.assertEqual(self.srv.request("GET", "/api/status", token=t1)[0], 401)
        _, _, data = self.srv.request("GET", "/api/status", token=t2)
        self.assertTrue(json.loads(data)["connected"])

    def test_explicit_logout_drops_the_tunnel_even_with_another_session(self):
        t1 = self.srv.login()
        t2 = self.srv.login()
        self.srv.request("POST", "/api/connect", {"server": "eu-west"}, token=t1)
        self.srv.request("POST", "/api/logout", {}, token=t2)
        self.assertEqual(self.srv.request("GET", "/api/status", token=t1)[0], 200)
        _, _, data = self.srv.request("GET", "/api/status", token=t1)
        self.assertFalse(json.loads(data)["connected"])


class Config(unittest.TestCase):

    def test_short_password_prints_warning(self):
        srv = Server(password="short-1")
        try:
            self.assertIn("shorter than 12 characters", srv.output())
            self.assertTrue(srv.login(password="short-1"))  # still accepted, just warned
        finally:
            srv.stop()

    def test_empty_password_env_generates_one(self):
        srv = Server(password="")
        try:
            status, _, _ = srv.request("POST", "/api/login", {"username": "demo", "password": ""})
            self.assertEqual(status, 401)  # an empty demo password is never accepted
            self.assertNotIn("from VPN_DEMO_PASSWORD", srv.output())
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
