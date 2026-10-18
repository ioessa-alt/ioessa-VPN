# Web Security Review: Mock VPN controller

Scope: `server.py`, `index.html`, `app.js`, `app.css` (project root only; `tunnel\` is out of scope).
Reference: *The Web Application Hacker's Handbook*, 2nd ed. (Stuttard & Pinto), chapters 2, 4, 5, 6, 7, 8, 12.
Status key: **defended** = control present and tested; **partly** = present with a gap; **open** = not addressed; **N/A** = feature does not exist.
Tests are in `test_web.py` (`python -m unittest test_web`, 26 tests).

## Findings, ranked

1. **UI did not run under its own CSP.** The page had an inline `<script>`, and the CSP was `default-src 'self'`, which blocks it. Headless Edge showed the login section still `hidden`. Fixed by moving script and CSS to `app.js` and `app.css`, with `script-src` falling back to `'self'` and no `unsafe-inline`.
2. **Username enumeration and lockout oracle.** A locked real account got `429`, an unknown or wrong one got `401`. The locked path also skipped PBKDF2, so response time differed. Fixed: every failed login returns the same `401` body, and each attempt costs one PBKDF2 run.
3. **Lockout race.** The failure count was checked, the lock released, the password verified, then the count incremented, so parallel guesses could exceed `MAX_FAILS`. Fixed: the attempt is counted under the lock before verification.
4. **Input handling.** Client-side `maxlength` was backed by silent truncation on the server (a password was cut to 256 characters). Fixed: oversized or non-string credentials are rejected as failed logins. POST bodies must be `application/json` (415), which also blocks cross-site form posts. Stock HTML error pages (which named the Python version) were replaced with JSON.
5. **DNS rebinding.** Requests with an unexpected `Host` header were accepted. Fixed: only `127.0.0.1:PORT` and `localhost:PORT` are accepted (403).
6. **Expired sessions were never pruned,** so memory grew with logins. Fixed: login prunes expired sessions and their tunnels.
7. **Config.** An empty `VPN_DEMO_PASSWORD` was accepted as a real password. Now it is treated as unset and a random one is generated. Passwords under 12 characters print a warning.
8. **Headers.** Added `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin`, `base-uri 'none'`, `form-action 'self'`, `object-src 'none'`.

## Chapter 2: Core Defense Mechanisms

| Claim (book) | Code location | Status | Test |
|---|---|---|---|
| Access to every function is controlled | `server.py` `do_GET` / `do_POST` (`_auth` before routing) | defended | `AuthAndInput.test_every_api_route_requires_a_session` |
| Input is handled to prevent malformed input from causing trouble | `_json_body`, `_login` type/length checks | defended | `test_invalid_json_and_non_object_are_400`, `test_malformed_credentials_get_the_same_answer`, `test_oversized_body_rejected_without_reading_it` |
| Attackers are handled (lockout, frustrating targeted attacks) | `check_login`, `MAX_FAILS`, `LOCKOUT` | partly | `Lockout.*` (see Ch 6 for the DoS gap) |
| Administrators can monitor and configure | Console output only; no audit log | open | none |
| Transport is protected | Loopback bind, plain HTTP | open (mock) | none; README lists it as a gap |

## Chapter 4: Mapping the Application

| Claim (book) | Code location | Status | Test |
|---|---|---|---|
| Enumeration of content and functions should reveal little | Unauthenticated requests get `401` before `404`, so unknown routes are not distinguished | defended | `test_every_api_route_requires_a_session`, `test_static_files_served_and_nothing_else` |
| Server banners and default error pages should not reveal details | `version_string`, `send_error` overrides | defended | `test_server_header_hides_python_version`, `test_unsupported_methods_get_json_errors` |
| Hidden or debug functionality is absent | No debug routes; only whitelisted static files (`STATIC`) | defended | `test_static_files_served_and_nothing_else` |
| Client-side source exposes the API surface | `app.js` names the API paths; unavoidable for a SPA; no secrets in client code | accepted | none |

## Chapter 5: Bypassing Client-Side Controls

| Claim (book) | Code location | Status | Test |
|---|---|---|---|
| Client-side input limits must be enforced on the server | `MAX_USERNAME`, `MAX_PASSWORD` in `_login` (rejected, not truncated) | defended (fixed) | `test_malformed_credentials_get_the_same_answer` |
| Data sent through the client must not be trusted | `connect` only accepts a key in `SERVERS`; tunnel state is server-side, keyed by session user | defended | `TunnelState.test_connect_rejects_unknown_server` |
| Client-side restrictions on UI actions are not security controls | Lockout and session checks run only on the server; the UI's disabled controls are cosmetic | defended | `Lockout.*`, `SessionExpiry.*` |

## Chapter 6: Attacking Authentication

| Claim (book) | Code location | Status | Test |
|---|---|---|---|
| Verbose failure messages must not reveal which part was wrong | Single `LOGIN_FAILED` body for unknown user, wrong password, lock, malformed input | defended (fixed) | `test_unknown_user_and_wrong_password_look_identical`, `Lockout.test_lockout_answer_matches_a_wrong_password` |
| Suspension must not reveal that a specific account is suspended | Locked and unknown answers are identical (`401`, same body) | defended (fixed) | `Lockout.test_lockout_answer_matches_a_wrong_password` |
| Timing must not reveal valid accounts | Every attempt runs one PBKDF2 (`verify_password`); locked path verifies against `DUMMY_HASH` | defended (fixed) | none (timing tests are flaky; the code path is the control) |
| A suspended account must not be checked, and suspension must not be bypassable by parallel guessing | Lock check and count reservation both happen under `LOCK` before verify | defended (fixed) | `Lockout.test_lockout_answer_matches_a_wrong_password` (serial only; no concurrency test) |
| Suspension should expire, and the counter should reset | `check_login` clears count after `locked_until` passes; success pops `FAILS` | defended | `Lockout.test_lockout_expires_and_counter_resets` |
| Lockout state must be bounded | `FAILS` only gets entries for accounts in `USERS` (fixed at startup) | defended | `Lockout.test_unknown_names_are_never_locked_and_do_not_grow_state` |
| Per-account suspension must not enable a DoS on real users | Anyone can lock `demo` for `LOCKOUT` seconds (5 bad passwords) | open | `Lockout.test_lockout_answer_matches_a_wrong_password` shows the lock; the DoS is accepted for a mock |
| Spraying one password across many accounts is limited | Per-account lock only; no per-IP limit, no CAPTCHA | open | none |
| Password quality is enforced | No policy; `VPN_DEMO_PASSWORD` under 12 characters prints a warning; empty value generates one | partly | `Config.test_short_password_prints_warning`, `Config.test_empty_password_env_generates_one` |
| Passwords are stored with a brute-force-resistant hash | `hash_password`: PBKDF2-SHA256, 600k rounds, 16-byte random salt | defended | exercised by every login test |
| Password change, recovery, and registration are protected | No such functions exist | N/A | none |

## Chapter 7: Attacking Session Management

| Claim (book) | Code location | Status | Test |
|---|---|---|---|
| Tokens come from a large, strong random source | `secrets.token_urlsafe(32)` (256 bits, OS CSPRNG) | defended | `AuthAndInput.test_login_token_is_long_random_and_unique` (format and uniqueness only) |
| Tokens carry no meaning or structure | Opaque random string; all session data is in `SESSIONS` | defended | same as above |
| Sessions expire, and the lifetime is kept short | `SESSION_TTL` (3600 s absolute), checked in `_auth`, pruned in `prune_expired` | partly | `SessionExpiry.test_session_expires_after_ttl` |
| Idle sessions are also expired (inactivity timeout) | None; only absolute TTL | open | none |
| Logout invalidates the token on the server | `/api/logout` pops `SESSIONS[token]` | defended | `AuthAndInput.test_logout_invalidates_token_on_server` |
| Session data and tunnel state are dropped with the session | Logout and expiry pop `TUNNELS[user]` | defended | `TunnelState.test_logout_drops_tunnel`, `SessionExpiry.test_expired_session_takes_its_tunnel_with_it` |
| Session fixation is prevented | No pre-login session; a new token is issued at each login | defended | by design |
| Token transport avoids CSRF | Bearer header, no cookies; cross-site POSTs cannot send `application/json` without preflight | defended (fixed) | `AuthAndInput.test_login_requires_json_content_type` |
| Token storage in the browser is acceptable (see decision below) | `sessionStorage` key `vpnToken` in `app.js` | partly | manual reasoning only |
| Concurrent sessions per user are limited | Unlimited | open | none |

**Storage decision (sessionStorage).** The token is kept in `sessionStorage`, not `localStorage`. It is scoped to one tab and cleared when the tab closes, so it does not persist across browser restarts. It is never sent automatically, so there is no CSRF exposure. The UI only inserts server data through `textContent` and `createElement`, so the usual XSS route to the token is not present in this code. This is acceptable for a simulation that runs on loopback over plain HTTP. A real controller should not do this: it should use an `HttpOnly`, `Secure`, `SameSite=Strict` cookie over HTTPS, which keeps the token away from script entirely.

## Chapter 8: Attacking Access Controls

| Claim (book) | Code location | Status | Test |
|---|---|---|---|
| Vertical: each user can only use functions for their role | No roles exist; no admin functions | N/A | none (becomes relevant if roles are added) |
| Horizontal: a user can only read or change their own resources | `TUNNELS` and `SESSIONS` are keyed by the authenticated username; no client-supplied user or object ID is used | defended by design | not exercised over HTTP: only one account (`demo`) exists |
| Object references are not guessable or user-supplied | Server IDs come from the fixed `SERVERS` dict; the connect body only selects one of them | defended | `TunnelState.test_connect_rejects_unknown_server` |
| Each API route checks authorization | `_auth` runs before every authenticated route; `/api/disconnect` and `/api/logout` act on the caller's own session only | defended | `AuthAndInput.test_every_api_route_requires_a_session` |

## Chapter 12: Cross-Site Scripting

| Claim (book) | Code location | Status | Test |
|---|---|---|---|
| Reflected XSS: user input is not echoed into HTML | Server returns JSON or fixed HTML; no input is echoed; `nosniff` set | defended | `HeadersAndUI.test_security_headers_on_page_and_api` |
| Stored XSS: stored data is output-encoded | Server data (city names) is constant; the UI uses `textContent` for everything it renders | defended | `HeadersAndUI.test_ui_script_uses_no_dangerous_dom_sinks` |
| DOM-based XSS: avoid HTML sinks; encode output | `app.js` has no `innerHTML`, `document.write`, `eval`, or `location`-driven logic; `textContent` and `replaceChildren` with `createElement` only | defended | `HeadersAndUI.test_ui_script_uses_no_dangerous_dom_sinks` (static guard) |
| CSP restricts script sources as a defense in depth | `script-src` falls back to `default-src 'self'`; no `unsafe-inline` or `unsafe-eval` | defended (fixed) | `HeadersAndUI.test_ui_has_no_inline_script_and_csp_allows_only_self` |
| Clickjacking is blocked | `X-Frame-Options: DENY`, `frame-ancestors 'none'` | defended | `HeadersAndUI.test_security_headers_on_page_and_api` |
