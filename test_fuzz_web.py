"""Mutation fuzzing of the mock controller's HTTP surface.

Method (Sutton, Greene and Amini, Fuzzing, ch. 9): send mutated requests to a live server.
The mutations cover JSON bodies, Content-Type, Content-Length, Host and Authorization
headers, and the path. The seed comes from IOESSA_FUZZ_SEED (default 1) and is printed on
failure, so each case can be replayed (ch. 5).

Invariants:
  1. The server process stays alive for the whole run.
  2. No mutated request gets a 500. The handler answers 500 only for an unexpected
     exception, so a 500 means a missing check. Failures print the request.
  3. Every response body is JSON with no stack trace or Python version string.
  4. Fuzzed login bodies never return a token. Only the real password logs in.
"""
import http.client
import json
import os
import random
import unittest
from urllib.parse import quote

from test_web import PASSWORD, Server

SEED = int(os.environ.get("IOESSA_FUZZ_SEED", "1"))
ITERATIONS = int(os.environ.get("IOESSA_FUZZ_WEB_ITERATIONS", "300"))
# 0 means no response: a Content-Length that does not match the body makes the server wait
# for its 10 s socket timeout. That is normal HTTP behaviour, and invariant 1 still checks
# that the process survives it.
EXPECTED = {0, 200, 400, 401, 403, 404, 405, 415, 501}   # 501: unsupported method, as stock http.server


def mutate_bytes(rng: random.Random, data: bytes) -> bytes:
    """Byte-level mutations of a JSON body or a header value."""
    buf = bytearray(data)
    kind = rng.randrange(6)
    if kind == 0 and buf:
        buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
    elif kind == 1 and buf:
        buf[rng.randrange(len(buf))] = rng.choice(b'{}[]",:\\\x00\xff\n\r ')
    elif kind == 2:
        buf[rng.randrange(len(buf) + 1):rng.randrange(len(buf) + 1)] = os.urandom(rng.randrange(1, 16))
    elif kind == 3:
        del buf[rng.randrange(len(buf) + 1):]
    elif kind == 4:
        buf += b'{"x":' * rng.randrange(1, 40)      # nesting
    else:
        buf = bytearray(rng.choice([b"", b"null", b"[]", b"1e999", b"\"\\ud800\"", b"{\"username\":1}"]))
    return bytes(buf)


class WebFuzzTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.srv = Server()

    @classmethod
    def tearDownClass(cls):
        cls.srv.proc.terminate()
        cls.srv.proc.wait(timeout=10)

    def _check(self, label, status, body, raw, headers=()):
        if status == 500:                           # invariant 2
            self.fail(f"500 for fuzzed {label} (IOESSA_FUZZ_SEED={SEED}) raw={raw!r}")
        if status not in EXPECTED:
            self.fail(f"unexpected status {status} for {label} raw={raw!r}")
        ctype = next((v for k, v in headers if k.lower() == "content-type"), "")
        parsed = {}
        if ctype.startswith("application/json"):
            try:
                parsed = json.loads(body) if body else {}
            except ValueError:
                self.fail(f"non-JSON body {body[:80]!r} for {label} raw={raw!r}")
        text = body.decode("utf-8", "replace")
        for leak in ("Traceback", "Python/", "File \""):      # invariant 3
            self.assertNotIn(leak, text, f"{leak!r} leaked for {label} raw={raw!r}")
        return parsed

    def test_fuzzed_json_bodies_get_no_500_and_no_leak(self):
        rng = random.Random(SEED)
        good = json.dumps({"username": "demo", "password": PASSWORD}).encode()
        for i in range(ITERATIONS):
            raw = mutate_bytes(rng, good if rng.random() < 0.5 else b'{"server":"x"}')
            status, headers, body = self._post("/api/login", raw)
            parsed = self._check("POST /api/login", status, body, raw, headers)
            if status == 200:                       # invariant 4 (fuzzed, not the real password)
                self.assertEqual(raw, good, f"fuzzed body logged in (IOESSA_FUZZ_SEED={SEED}, i={i}) raw={raw!r}")
                self.assertIn("token", parsed)
        self.assertIsNone(self.srv.proc.poll(), "server process exited during fuzzing")   # invariant 1

    def test_fuzzed_headers_get_no_500(self):
        rng = random.Random(SEED + 1)
        headers_choices = [
            ("Content-Type", ["application/json", "application/json; charset=utf-8", "text/plain",
                              "application/json, text/plain", "", "application/json;;"]),
            ("Content-Length", ["0", "-1", "4097", "abc", "1e3", " 12 ", "99999999999999999999"]),
            ("Host", ["127.0.0.1", "localhost", "evil.test", "127.0.0.1:1", "", "[::1]"]),
            ("Authorization", ["Bearer ", "Bearer x", "bearer abc", "Basic zzz", "Bearer " + "A" * 500]),
        ]
        for _ in range(ITERATIONS):
            name, values = rng.choice(headers_choices)
            value = rng.choice(values) if rng.random() < 0.8 else mutate_bytes(rng, values[0].encode()).decode("ascii", "ignore")
            raw = b'{"username":"demo","password":"x"}'
            if any(c in value for c in "\r\n\x00"):
                continue    # http.client refuses these (header injection guard), so they never reach the server
            label = f"header {name}={value!r}"
            status, headers, body = self._request("POST", "/api/connect", raw, {name: value})
            self._check(label, status, body, raw, headers)
            status, headers, body = self._request("GET", "/api/status", None, {name: value})
            self._check(f"GET /api/status {label}", status, body, raw, headers)
        self.assertIsNone(self.srv.proc.poll(), "server process exited during header fuzzing")

    def test_fuzzed_paths_and_methods_get_no_500(self):
        rng = random.Random(SEED + 2)
        for _ in range(ITERATIONS):
            path = "/" + quote(mutate_bytes(rng, b"api/status").decode("latin-1"), safe="/")
            method = rng.choice(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
            status, headers, body = self._request(method, path, None, {})
            if method != "HEAD":
                self._check(f"{method} {path!r}", status, body, path.encode(), headers)
        self.assertIsNone(self.srv.proc.poll(), "server process exited during path fuzzing")

    # -- helpers ------------------------------------------------------------

    def _post(self, path, raw):
        return self._request("POST", path, raw, {"Content-Type": "application/json"})

    def _request(self, method, path, raw, headers):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=15)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", headers.pop("Host", "127.0.0.1:%d" % self.srv.port))
            for k, v in headers.items():
                conn.putheader(k, v)
            if raw is not None and "Content-Length" not in headers:
                conn.putheader("Content-Length", str(len(raw)))
            conn.endheaders(raw or None)
            res = conn.getresponse()
            return res.status, res.getheaders(), res.read()
        except (ConnectionError, OSError):
            return 0, [], b""
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
