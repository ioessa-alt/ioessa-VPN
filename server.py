"""Mock VPN control plane + UI host.

SIMULATION ONLY: no tunnel is created and no traffic is routed. It exists to
exercise the auth, session, and UI flow of a VPN client/controller.
Standard library only (Python 3.9+).
"""
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"  # never bind an authenticated mock to 0.0.0.0
PORT = int(os.environ.get("VPN_PORT", "8787"))
UI_FILE = Path(__file__).with_name("index.html")
STATIC = {  # the only static files served; no path is built from the request
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
SESSION_TTL = int(os.environ.get("VPN_SESSION_TTL", "3600"))  # seconds, absolute
SESSION_IDLE = int(os.environ.get("VPN_SESSION_IDLE", "900"))  # seconds without a request
MAX_SESSIONS_PER_USER = int(os.environ.get("VPN_MAX_SESSIONS", "5"))  # oldest is evicted at login
LOCKOUT = int(os.environ.get("VPN_LOCKOUT_SECONDS", "60"))    # seconds
MAX_BODY = 4096      # bytes
MAX_USERNAME = 64    # characters, matches the UI maxlength
MAX_PASSWORD = 256
MAX_FAILS = 5        # failed logins before lockout
PBKDF2_ROUNDS = 600_000
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}  # DNS rebinding guard

SERVERS = {
    "eu-west": {"city": "Dublin", "prefix": "10.8.0."},
    "us-east": {"city": "New York", "prefix": "10.9.0."},
    "ap-south": {"city": "Singapore", "prefix": "10.10.0."},
}

# One generic answer for every failed login: unknown user, wrong password,
# locked account, or malformed credentials. Same status, same body.
LOGIN_FAILED = {"error": "invalid credentials or too many attempts, try again later"}

TLS_ON = False   # set by main() when VPN_TLS_CERT and VPN_TLS_KEY are given
LOCK = threading.Lock()
USERS = {}       # username -> "salt_hex$digest_hex" (written once, at startup)
SESSIONS = {}    # token -> (username, expires_at, last_seen)
TUNNELS = {}     # username -> simulated tunnel state
FAILS = {}       # username -> (count, locked_until); only real accounts, so bounded


class UnsupportedMedia(Exception):
    pass


ACCOUNT_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")


def load_accounts(spec: str):
    """Extra accounts from VPN_ACCOUNTS, written as name:password pairs separated by commas (open issue 18).
    Names are lowercase letters, digits, '-' or '_'. Passwords must be 12 to 256 characters. A bad entry
    stops the server, so a typo cannot silently drop an account."""
    out = []
    for item in (s.strip() for s in spec.split(",") if s.strip()):
        name, sep, pw = item.partition(":")
        if not sep or not ACCOUNT_NAME.fullmatch(name) or name == "demo":
            raise SystemExit("VPN_ACCOUNTS: each entry must be name:password, with a valid name and not 'demo'")
        if not 12 <= len(pw) <= MAX_PASSWORD:
            raise SystemExit(f"VPN_ACCOUNTS: the password for {name} must be 12 to 256 characters")
        out.append((name, pw))
    names = [n for n, _ in out]
    if len(names) != len(set(names)):
        raise SystemExit("VPN_ACCOUNTS: a name appears more than once")
    return out


def audit(event: str, user: str, src: str, **fields) -> None:
    """One line per security event (open issue 16). Passwords and tokens are never logged. The user name
    is shown with repr(), so a name that contains a newline cannot forge a second line."""
    extra = "".join(f" {k}={v}" for k, v in fields.items())
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} audit event={event} user={user!r:.80} src={src}{extra}",
          flush=True)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), PBKDF2_ROUNDS)
    return hmac.compare_digest(digest.hex(), digest_hex)


# Used when a username is unknown or locked, so every login attempt costs one
# PBKDF2 run and response time does not reveal valid or locked accounts.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def check_login(username: str, password: str) -> bool:
    """Return True only for a correct password on an unlocked real account.

    Every call does exactly one PBKDF2 computation. The attempt is counted
    before the password is checked, under the lock, so concurrent guesses
    cannot run past MAX_FAILS. A correct password clears the count.
    """
    now = time.time()
    tracked = username in USERS  # USERS is fixed after startup
    locked = False
    if tracked:
        with LOCK:
            count, locked_until = FAILS.get(username, (0, 0))
            if locked_until > now:
                locked = True
            else:
                if locked_until:  # lockout expired, start counting again
                    count = 0
                count += 1
                FAILS[username] = (count, now + LOCKOUT if count >= MAX_FAILS else 0)
    if locked:
        verify_password(password, DUMMY_HASH)  # do not check credentials while locked
        return False
    ok = tracked and verify_password(password, USERS.get(username, DUMMY_HASH))
    if ok:
        with LOCK:
            FAILS.pop(username, None)
    return ok


def is_stale(entry, now: float) -> bool:
    """A session is stale past its absolute expiry or after SESSION_IDLE without a request."""
    _, expires, last_seen = entry
    return expires < now or now - last_seen > SESSION_IDLE


def drop_session(token: str) -> None:
    """Remove one session. The user's tunnel goes only with their last session. Caller holds LOCK."""
    user = SESSIONS.pop(token)[0]
    if not any(u == user for u, _, _ in SESSIONS.values()):
        TUNNELS.pop(user, None)


def prune_expired(now: float) -> None:
    """Drop stale sessions and tunnels left without a session. Caller must hold LOCK."""
    for token in [t for t, entry in SESSIONS.items() if is_stale(entry, now)]:
        drop_session(token)


def status_for(user: str) -> dict:
    with LOCK:
        t = TUNNELS.get(user)
    if not t:
        return {"connected": False, "mode": "simulation"}
    up = time.time() - t["since"]
    return {
        "connected": True,
        "mode": "simulation",
        "server": t["server"],
        "city": SERVERS[t["server"]]["city"],
        "vip": t["vip"],
        "uptime": int(up),
        # Fake counters that grow with time, purely for the UI.
        "rx": int(up * 48_000),
        "tx": int(up * 12_000),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "MockVPN"
    timeout = 10  # drop idle sockets so slow clients cannot pin threads

    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def version_string(self):  # no Python version in the Server header
        return self.server_version

    def send_error(self, code, message=None, explain=None):
        # Replace the stock HTML error page (which names the Python version)
        # with the same JSON shape the API uses.
        self._send(code, {"error": http.client.responses.get(code, "error").lower()})

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if TLS_ON:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; form-action 'self'; "
            "object-src 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self):
        return (self.headers.get("Host") or "").lower() in ALLOWED_HOSTS

    def _json_body(self):
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise UnsupportedMedia()
        length = int(self.headers.get("Content-Length") or 0)
        if not 0 <= length <= MAX_BODY:
            raise ValueError("body size")
        data = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data

    def _auth(self):
        header = self.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        now = time.time()
        with LOCK:
            entry = SESSIONS.get(token)
            if entry is None:
                return None, None
            if is_stale(entry, now):
                drop_session(token)
                return None, None
            user, expires, _ = entry
            SESSIONS[token] = (user, expires, now)  # a request counts as activity
        return user, token

    def do_GET(self):
        try:
            if not self._host_ok():
                return self._send(403, {"error": "forbidden"})
            if self.path in ("/", "/index.html"):
                return self._send(200, UI_FILE.read_bytes(), "text/html; charset=utf-8")
            if self.path in STATIC:
                name, ctype = STATIC[self.path]
                return self._send(200, UI_FILE.with_name(name).read_bytes(), ctype)
            user, _ = self._auth()
            if user is None:
                return self._send(401, {"error": "not authenticated"})
            if self.path == "/api/servers":
                return self._send(200, [{"id": k, "city": v["city"]} for k, v in SERVERS.items()])
            if self.path == "/api/status":
                return self._send(200, status_for(user))
            self._send(404, {"error": "not found"})
        except Exception:
            self._send(500, {"error": "internal error"})

    def do_POST(self):
        try:
            if not self._host_ok():
                return self._send(403, {"error": "forbidden"})
            if self.path == "/api/login":
                return self._login(self._json_body())
            user, token = self._auth()
            if user is None:
                return self._send(401, {"error": "not authenticated"})
            if self.path == "/api/connect":
                return self._connect(user, self._json_body())
            if self.path == "/api/password":
                return self._password(user, token, self._json_body())
            if self.path == "/api/disconnect":
                with LOCK:
                    TUNNELS.pop(user, None)
                audit("disconnect", user, self.client_address[0])
                return self._send(200, {"connected": False})
            if self.path == "/api/logout":
                with LOCK:
                    SESSIONS.pop(token, None)
                    TUNNELS.pop(user, None)  # an explicit logout always ends the tunnel
                audit("logout", user, self.client_address[0])
                return self._send(200, {"ok": True})
            self._send(404, {"error": "not found"})
        except UnsupportedMedia:
            self._send(415, {"error": "content-type must be application/json"})
        except ValueError:
            self._send(400, {"error": "bad request"})
        except Exception:
            self._send(500, {"error": "internal error"})

    def _login(self, body):
        src = self.client_address[0]
        username = body.get("username")
        password = body.get("password")
        if (not isinstance(username, str) or not isinstance(password, str)
                or len(username) > MAX_USERNAME or len(password) > MAX_PASSWORD):
            # Malformed input is treated like a failed attempt, not a 400, so
            # it does not reveal anything beyond "invalid credentials".
            check_login("", "")
            audit("login.fail", "?", src, reason="malformed")
            return self._send(401, LOGIN_FAILED)
        if not check_login(username, password):
            audit("login.fail", username, src, reason="invalid or locked")
            return self._send(401, LOGIN_FAILED)
        audit("login.ok", username, src)
        now = time.time()
        with LOCK:
            prune_expired(now)
            mine = sorted((t for t, (u, _, _) in SESSIONS.items() if u == username),
                          key=lambda t: SESSIONS[t][2])
            evicted = mine[:max(0, len(mine) - MAX_SESSIONS_PER_USER + 1)]
            for old in evicted:
                SESSIONS.pop(old)                   # evict the least recently used; tunnel stays
            token = secrets.token_urlsafe(32)  # 256 bits from the OS CSPRNG
            SESSIONS[token] = (username, now + SESSION_TTL, now)
        if evicted:
            audit("session.evict", username, src, count=len(evicted))
        self._send(200, {"token": token, "expires_in": SESSION_TTL})

    def _password(self, user, token, body):
        """Change the signed-in user's password (open issue 17). The current password is checked with
        check_login, so wrong guesses count toward the lockout. Other sessions of the user are ended."""
        src = self.client_address[0]
        current, new = body.get("current"), body.get("new")
        if not isinstance(current, str) or not isinstance(new, str):
            raise ValueError("expected current and new")
        if not 12 <= len(new) <= MAX_PASSWORD:
            return self._send(400, {"error": "new password must be 12 to 256 characters"})
        if not check_login(user, current):
            audit("password.fail", user, src)
            return self._send(401, LOGIN_FAILED)
        stored = hash_password(new)                 # slow, so computed outside the lock
        with LOCK:
            USERS[user] = stored
            others = [t for t, (u, _, _) in SESSIONS.items() if u == user and t != token]
            for t in others:
                SESSIONS.pop(t)
        audit("password.change", user, src, other_sessions_ended=len(others))
        self._send(200, {"ok": True})

    def _connect(self, user, body):
        name = body.get("server")
        if not isinstance(name, str) or name not in SERVERS:
            return self._send(400, {"error": "unknown server"})
        vip = SERVERS[name]["prefix"] + str(secrets.randbelow(230) + 20)
        with LOCK:
            TUNNELS[user] = {"server": name, "since": time.time(), "vip": vip}
        audit("connect", user, self.client_address[0], server=name)
        self._send(200, status_for(user))


def main():
    password = os.environ.get("VPN_DEMO_PASSWORD")
    generated = not password  # unset or empty: generate one
    if generated:
        password = secrets.token_urlsafe(12)
    elif len(password) < 12:
        print("Warning: VPN_DEMO_PASSWORD is shorter than 12 characters.")
    USERS["demo"] = hash_password(password)
    extra = load_accounts(os.environ.get("VPN_ACCOUNTS", ""))
    for name, pw in extra:
        USERS[name] = hash_password(pw)
    if extra:
        print("Accounts from VPN_ACCOUNTS: " + ", ".join(name for name, _ in extra))

    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    scheme = "http"
    cert, key = os.environ.get("VPN_TLS_CERT"), os.environ.get("VPN_TLS_KEY")
    if cert or key:
        # HTTPS when both files are given (open issue 15). The operator supplies the certificate. The
        # mock cannot make one, since it is standard library only. A self-signed certificate works for a
        # local demo, but the browser will warn about it.
        if not (cert and key):
            raise SystemExit("VPN_TLS_CERT and VPN_TLS_KEY must be set together")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(cert, key)
        except (OSError, ssl.SSLError) as e:
            raise SystemExit(f"VPN_TLS_CERT / VPN_TLS_KEY could not be loaded: {e}")
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        global TLS_ON
        TLS_ON = True
        scheme = "https"
    print(f"Mock VPN UI: {scheme}://{HOST}:{PORT}")
    print("Login: demo / " + (password if generated else "(from VPN_DEMO_PASSWORD)"))
    print("Simulation only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
