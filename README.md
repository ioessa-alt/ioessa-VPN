# Mock VPN

A simulated VPN client and controller for learning the auth, session, and UI flow.
**It does not create a tunnel or route traffic.**

## Run

```powershell
python server.py                       # prints a generated password for user "demo"
$env:VPN_DEMO_PASSWORD="your-long-pass-here"; python server.py   # or set your own (12+ characters)
```

Open http://127.0.0.1:8787

Optional environment variables (for testing or tuning): `VPN_PORT` (default 8787),
`VPN_LOCKOUT_SECONDS` (60), `VPN_SESSION_TTL` (3600 s, absolute), `VPN_SESSION_IDLE` (900 s without a request),
`VPN_MAX_SESSIONS` (5 per user; the least recently used is evicted at login).

HTTPS (optional): set `VPN_TLS_CERT` and `VPN_TLS_KEY` to PEM files. Both are required together. The mock
cannot create a certificate itself (it is standard library only), so make one with your usual tool. Browsers
warn about a self-signed certificate. HSTS is sent when HTTPS is on.

Extra accounts: `VPN_ACCOUNTS="alice:<password>,bob:<password>"` (names are lowercase letters, digits, `-`, `_`;
passwords 12 to 256 characters; a bad entry stops the server). Passwords in an environment variable are
visible to the same user's processes, so treat this as a demo setting.

Each sign-in, failed sign-in, connect, disconnect, logout, and password change prints one `audit` line with a
timestamp. Passwords and tokens are never printed.

Run the tests from this folder with `python -m unittest test_web`.
The web security review is in `WEB_SECURITY_REVIEW.md`.

## Security choices

- Binds to `127.0.0.1` only. Requests whose `Host` is not `127.0.0.1` or `localhost` get 403 (DNS rebinding guard).
- Passwords stored as PBKDF2-SHA256 (600k rounds, random salt), compared in constant time.
- Every failed login returns the same `401` body, whether the user is unknown, the password is wrong, or the account is locked. Each attempt costs one PBKDF2 run, so timing does not separate these cases either.
- Lockout after 5 failed logins for 60 seconds. Only real accounts are tracked, so the lockout state is bounded.
- Opaque random bearer tokens (256 bits) with a 1-hour TTL. Logout and expiry drop the token and the tunnel. Expired sessions are pruned at login.
- POST bodies must be `application/json` (415 otherwise). Body limit is 4 KB; oversized, malformed, or non-object bodies get 400.
- Errors are JSON with generic messages; no stack traces, and the `Server` header does not name the Python version.
- Response headers: CSP `default-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'`, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin`, `no-store`.
- The UI script and styles are separate files (`app.js`, `app.css`), so the CSP needs no `unsafe-inline`. The UI renders all server data with `textContent`, never `innerHTML`.
- The UI keeps the bearer token in `sessionStorage` (per tab, cleared on close). See the storage decision in `WEB_SECURITY_REVIEW.md`.

## Known gaps (this is a mock)

- No TLS. A real VPN control plane must be HTTPS only, with the token in an `HttpOnly`, `Secure`, `SameSite` cookie instead of `sessionStorage`.
- In-memory state; accounts and sessions reset on restart. Accounts come from `demo` and `VPN_ACCOUNTS`. Each account has its own tunnel state, which the tests check over HTTP.
- Lockout by username lets anyone lock out an account for 60 seconds. A real service needs a softer policy or an out-of-band recovery path. There is no password recovery: a forgotten password needs a restart with a new setting.
- No rate limiting by IP, no CAPTCHA, so one password can still be tried against many usernames. The server listens on loopback only, so a per-IP limit would count every client as one address.
- The generated demo password is printed to the console.
- Traffic counters are fake, derived from elapsed time.
- Password change is available at `POST /api/password`. It needs the current password, and the new one must be 12 to 256 characters. It ends the user's other sessions.
- Transport is plain HTTP on loopback. TLS is deliberately not added to this mock. A real deployment needs HTTPS, as noted above.

For a real tunnel, look at WireGuard (`wg`) or OpenVPN, which need admin rights and a TUN driver.

## License and security reports

MIT, see `LICENSE`. To report a vulnerability, see `SECURITY.md`.
