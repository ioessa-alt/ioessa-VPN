# Open issues: consolidated

Collected on 2026-10-16 from the review documents in this folder and in the project root. Each item
is a known gap that its source document still lists as open, not fixed, partly met, or not verified.
Duplicates are merged; the first source named is the main one.

**Severity.** Where the source gives a rating, it is used and named in the source column. Where the
source gives none, the severity in the table is marked "(assigned)" and is this pass's judgement.
"Not rated" means the source lists the item as a gap but gives no rating and none was assigned.

Items the source itself says are stale have been corrected in place in their documents and are not
listed here. The root web mock is listed under "Operations and privileges" because its controls are
operational.

## Protocol and crypto

| # | Open item | Severity | Source |
|---|---|---|---|
| 1 | A flood from many spoofed sources is not bounded. The per-source INIT budget covers real addresses only, and there is no bandwidth cap. Cookies bound CPU per source only | Medium | SECURITY_ENGINEERING_REVIEW 9 item 2; THREAT_MODEL P-D3, U-D5 |
| 2 | A leaked responder X25519 key alone no longer lets an attacker pose as a client (the ML-KEM secret is also needed). Leaking both keys still does, unless a PSK is set. The PSK is one shared secret for all peers | Medium (design) | SECURITY_ENGINEERING_REVIEW 9 item 1 (cites K-X1, H-X11) |
| 3 | Revocation needs a restart when peers come from the environment. With ``--peer-key-file`` the server re-reads the file about every 5 s (peer_reload.py), so a removed key stops working without a restart | Closed for file-based peers | KEY_LIFECYCLE 5 gap 1; SRE_REVIEW 11 item 6 |
| 4 | Forward secrecy is per session (about 120 s). No per-message ratchet and no post-compromise security against an active attacker | Medium (design) | CRYPTO_REVIEW F5, Remaining risks 2 |
| 5 | A retransmitted INIT is not bitwise identical to the first (RFC 7296 2.1 deviation). A lost RESP is recovered only by the next attempt | Not rated (assigned Low) | RFC7296_REVIEW 2.1 ("Open, deviation") |
| 6 | No SA lifetime by byte count. Only time and message count are used | Not rated (assigned Low) | NETWORK_SECURITY_REVIEW 4 item 4, 8 |
| 7 | Session and key material stays in Python memory. No zeroing, which Python cannot guarantee | Low (platform limit) | CRYPTO_REVIEW F6, Remaining risks 3; SECURITY_ENGINEERING_REVIEW 8 |
| 8 | No wire version field, so there is no migration path for the protocol | Low | SECURITY_ENGINEERING_REVIEW 9 item 4 |
| 9 | Transport key derivation differs from Noise `Split()`. Stated as a deviation, not a known weakness | Not rated (assigned Low) | CRYPTO_REVIEW Remaining risks 5 |
| 10 | No backup server key and no pin-update path | Low | KEY_LIFECYCLE 5 gap 3, section 4 |
| 11 | No key-age record and no rotation schedule. Rotation is manual | Low | KEY_LIFECYCLE 5 gap 4; ZERO_TRUST_REVIEW (physical coercion row) |
| 12 | Server-key overlap: the client now tries every configured key, but the server holds one private key at a time, so a server key change still needs a cut-over window | Not rated (assigned Low) | KEY_LIFECYCLE 3.2, 5 gap 2 (partly fixed) |
| 13 | Revoked-key attempts are not logged. A removed key looks like any unknown key | Low | KEY_LIFECYCLE 5 gap 6 |
| 14 | Replay state is in RAM by default. Without `--state-file`, a restart reopens replay for captured INITs (a warning is printed). The state-file fix is opt-in | Low (residual) | CRYPTO_REVIEW F9; README "Restart and replay state" |
| 15 | Entropy of an operator-supplied PSK or key file is not checked. Only length is checked. PSK rotation is not checked | Not rated (assigned Low) | RANDOMNESS_REVIEW 5; THREAT_MODEL 5 |
| 16 | Timestamps are wall-clock. A clock set backwards would weaken the INIT replay check. The current rule has no freshness window, so a captured INIT that is held back can be accepted later (suppress-replay). `model_check_init.py` finds this trace (send 1, deliver 1 at 4) and shows that a 2 s window removes it. Replay safety holds in both | Not rated (assigned Low) | RANDOMNESS_REVIEW 6 item 5; `test_model_init.py` |
| 17 | The cookie secret rotates lazily, only when an INIT arrives. An idle node keeps an older secret | Low | THREAT_MODEL 5; RANDOMNESS_REVIEW 6 item 4 |
| 18 | The crypto-failure log reason is generic. A bad transcript and a wrong responder key look the same | Low | SRE_REVIEW 11 item 11; SRE_REVIEW table (crypto failures) |
| 19 | The receive path has no per-packet session-age check. Expiry runs once per tick | Not rated (assigned Low) | README "Open gaps"; ZERO_TRUST_REVIEW (check A note) |
| 20 | Traffic analysis is not stopped: packet sizes, timing and endpoints are visible. Padding is 0 to 3 bytes; indices are in clear | Accepted (not rated) | THREAT_MODEL 7 (U-I1) |
| 21 | Side channels from the Python interpreter (timing, memory copies, GC) are not covered. Only the secret comparisons are constant-time | Not rated | THREAT_MODEL 5; SIDE_CHANNEL_REVIEW 1 |
| 22 | Impersonation needs both the X25519 and the ML-KEM-768 private key of a peer. A stolen ML-KEM key (static, not rotated) exposes the sessions it protected. Rotation is manual (vpn_keygen.py) | Medium | CRYPTO_REVIEW F10; THREAT_MODEL H-Q2 |
| 23 | The ML-KEM-768 handshake has not been audited and has no independent transcript check. Nothing is checked against a second implementation | Medium | CRYPTO_REVIEW F10 |

## Operations and privileges

| # | Open item | Severity | Source |
|---|---|---|---|
| 22 | Impersonation needs both the X25519 and the ML-KEM-768 private key of a peer. A stolen ML-KEM key (static, not rotated) exposes the sessions it protected. Rotation is manual (vpn_keygen.py) | Medium | CRYPTO_REVIEW F10; THREAT_MODEL H-Q2 |
| 23 | The ML-KEM-768 handshake has not been audited and has no independent transcript check. Nothing is checked against a second implementation | Medium | CRYPTO_REVIEW F10 |
| 24 | Key files are not permission-checked on read on POSIX-only terms. Windows now checks the ACL with `icacls` (`_check_windows_acl`), but names are matched in English, so a localized Windows may refuse a file that is fine. Closed for English Windows | Not rated (assigned Low) | SRE_REVIEW table (K-I3); CRYPTO_REVIEW F7, Remaining risks 4 |
| 25 | `vpn_keygen.py` prints the private key to stdout when `--out` is not given | Low | OPERATIONS_REVIEW 9; KEY_LIFECYCLE 5 gap 5 |
| 26 | TUN mode accepts only one peer. Per-peer routes are not configurable, so the server refuses to start with two or more peers | Not rated (assigned Medium) | README "Open gaps"; SANS_REVIEW finding 1 (partly met) |
| 27 | A compromised but authenticated client is not in the threat model, and there is no `/32` route per client | Not rated (assigned Medium) | SANS_REVIEW finding 2 |
| 28 | IPv6 outside the tunnel is not mitigated: the host may send IPv6 outside the tunnel | Not rated (assigned Medium) | THREAT_MODEL 6 (Open); OPERATIONS_REVIEW 8; SANS_REVIEW table (IPv6) |
| 29 | The peer file is read once at start. It has no hash, no integrity check, and the log shows only a count | Not rated (assigned Low) | SRE_REVIEW table (peer list); KEY_LIFECYCLE 1 |
| 30 | The state file has no integrity or age check. Deleting it or restoring an older copy reopens replay. Two processes on one file are not coordinated | Not rated (assigned Medium) | SANS_REVIEW finding 9; THREAT_MODEL 7 (state-file row) |
| 31 | Logs have no timestamps, no levels, no log file and no rotation. There is no remote or immutable copy | Medium | SANS_REVIEW finding 3; OPERATIONS_REVIEW 3, 9; SRE_REVIEW table (logging) |
| 32 | Rekey starts and silent drops are not logged. The client has no rejection counter | Not rated | OPERATIONS_REVIEW 9 |
| 33 | The log file is not capped in code. Printed refusals are budgeted, but the file grows with attacker volume if stdout is redirected | Not rated (assigned Low) | OPERATIONS_REVIEW 3 (storage) |
| 34 | No network access control or posture check. A client with a valid key is not checked for health | Not rated | SANS_REVIEW finding 2; OPERATIONS_REVIEW 9 |
| 35 | Cookie replies and the "under load" printed line are not throttled. Volume is about 0.49 times the request | Not rated | SRE_REVIEW 11 item 2; SRE_REVIEW table (cookie replies) |
| 36 | No request priority and no load shedding. All INITs are equal | Not rated (declared not needed) | SRE_REVIEW table (request priority) |
| 37 | Any exception other than `HandshakeError` and `ESPError` ends `serve()` | Not rated | OPERATIONS_REVIEW 9 |
| 38 | Ctrl+C on the server ends with a traceback. Read from the code, not run | Low | OPERATIONS_REVIEW 9 |
| 39 | Windows TUN (Wintun) is not implemented. `QueueTun` is in memory only | Not rated | README "Not done"; THREAT_MODEL 5, D-E1 |
| 40 | Hardware and OS-level attacks (fault injection, Rowhammer, CLKscrew, Spectre) are open. Out of scope for this prototype | Not rated (declared out of scope) | SECURITY_ENGINEERING_REVIEW chapter 19 table |
| 41 | No vulnerability disclosure policy or contact. No incident response plan | Not rated | SECURITY_ENGINEERING_REVIEW 27.5.7 and release table |
| 42 | Zero-trust gap: the server accepts any peer with a pinned key, with no per-host or per-role check beyond `allowed_ips` | Not rated | ZERO_TRUST_REVIEW 1.2 (Not met) |
| 43 | Demo setting: queue-mode `allowed_ips` defaults to any source | Low (assigned) | ZERO_TRUST_REVIEW (note near line 165) |
| 44 | Web mock: transport is plain HTTP on loopback, with no TLS. The bearer token is in `sessionStorage` | Not rated (mock) | WEB_SECURITY_REVIEW ch. 2, ch. 7; root README "Known gaps" |
| 45 | Web mock: no audit log. Administrators cannot monitor or configure beyond console output | Not rated (mock) | WEB_SECURITY_REVIEW ch. 2 |
| 46 | Web mock: anyone can lock the `demo` account for 60 s with 5 bad passwords | Not rated (mock; accepted) | WEB_SECURITY_REVIEW ch. 6; root README |
| 47 | Web mock: no per-IP limit and no CAPTCHA. One password can be tried against many usernames | Not rated (mock) | WEB_SECURITY_REVIEW ch. 6; root README |
| 48 | Web mock: no idle timeout. Only the 3600 s absolute TTL applies | Not rated (mock) | WEB_SECURITY_REVIEW ch. 7; root README |
| 49 | Web mock: no limit on concurrent sessions per user | Not rated (mock) | WEB_SECURITY_REVIEW ch. 7 |
| 50 | Web mock: no password change or recovery. Password policy is a startup warning under 12 characters only | Not rated (mock) | WEB_SECURITY_REVIEW ch. 6; root README |
| 51 | Web mock: the generated demo password is printed to the console | Not rated (mock) | root README "Known gaps" |
| 52 | Web mock: traffic counters are fake, derived from elapsed time | Not rated (mock) | root README "Known gaps" |

## Testing and verification

| # | Open item | Severity | Source |
|---|---|---|---|
| 53 | The Linux TUN device has never been created, configured or pinged on a kernel. The `TUNSETIFF` and `ifreq` values come from memory, not a header on disk | Medium (assigned) | README "Verified and not verified"; THREAT_MODEL 6 ("still open"); NETWORK_SECURITY_REVIEW 8 |
| 54 | The netns and veth example in the README has not been run | Not rated | README "Not verified" |
| 55 | Real network: tested on 127.0.0.1 only. No NAT traversal, no path-MTU work, and no packet-loss test beyond unit tests | Not rated | README "Not done or not verified"; THREAT_MODEL 5 |
| 56 | Timers are tested with a fake clock only. Rekey and keepalive on a real clock were not exercised | Not rated | README "Not verified"; THREAT_MODEL 5; ZERO_TRUST_REVIEW 9 |
| 57 | Official Noise and WireGuard test vectors were not obtained (404 at every URL tried). Interop with `wg` is not tested | Not rated | CRYPTO_REVIEW F2, Remaining risks 1; THREAT_MODEL 5 |
| 58 | ESP padding content is not checked against RFC 4303 or the book | Not rated | NETWORK_SECURITY_REVIEW 8 |
| 59 | No coverage-guided fuzzing. Only a seeded mutation test exists (300 rounds each for handshake and data). The TUN backend is not fuzzed | Low | SECURITY_ENGINEERING_REVIEW 9 item 5; SRE_REVIEW 11 item 10; THREAT_MODEL 5 |
| 60 | No static analysis, and no type or security linter has been run | Low | SECURITY_ENGINEERING_REVIEW 9 item 5, table (tools) |
| 61 | No independent review. All reviews are by the author or by agents working on this repo | Low | SECURITY_ENGINEERING_REVIEW 9 item 5, table (independent review) |
| 62 | No formal proof of the handshake or the data path. Arguments are informal | Not rated | THREAT_MODEL 5; README "Not done or not verified" |
| 63 | Recovery is tested only for replay after restart. Restart followed by rekey, and rebuild from an empty peer list, are not tested | Not rated | SRE_REVIEW table (recovery); SRE_REVIEW 11 item 10 |
| 64 | Tag checks delegated to the `cryptography` library were not verified in the side-channel review | Not rated | SIDE_CHANNEL_REVIEW 1 (counts) |
| 65 | Web mock: the lockout race has no concurrency test. Timing tests are not used (flaky), so timing is covered by code path only | Not rated | WEB_SECURITY_REVIEW ch. 6 |
| 66 | Web mock: only one account exists, so cross-user isolation is not exercised over HTTP | Not rated | WEB_SECURITY_REVIEW ch. 8; root README |
| 67 | `analysis/analyze.py` line 42: `DATA_MIN_LEN` is 34, but a keepalive is 36 bytes on the wire. The value is a lower bound, so no valid packet is rejected, but the comment is wrong. `analysis/` was not changed in this pass | Low | SANS_REVIEW finding 7 |

## Documentation

| # | Open item | Severity | Source |
|---|---|---|---|
| 68 | The startup warning in `vpn_server.py` (lines 218-221) says a replayed INIT "moves that peer's endpoint". The endpoint no longer moves on an INIT (README lines 83-84; `test_replayed_init_after_restart_does_not_move_endpoint`). Fixed: the warning now says the replay gives no keys and does not move the endpoint. Tests pass | Closed | vpn_server.py 218-221; README 83-84 |
| 69 | THREAT_MODEL P-D1 says each failure is caught and logged. Only `HandshakeError` and `ESPError` are caught inside `Node` | Low | OPERATIONS_REVIEW 9; THREAT_MODEL P-D1 |
| 70 | README says the ICMP fragmentation-needed rule is "not from the book". SANS_REVIEW finding 5 says the course does cover it (OCR lines 3982, 4028-4031) and asks for those citations | Low | README (firewall rule 4); SANS_REVIEW finding 5 |
| 71 | OPERATIONS_REVIEW section 1 has two wrong corrections: CDP also appears in Module 5 (OCR 5569-5571), and the IPsec mentions are incomplete (OCR 3765, 5570) | Low | SANS_REVIEW finding 6 |
| 72 | TLS comparison is based on the book's description only. No TLS code was run | Not rated | NETWORK_SECURITY_REVIEW 8 |
| 73 | `vpn_core.py` (835 lines) mixes protocol, config, TUN and helpers. Splitting it is out of scope for this prototype | Not rated (declared out of scope) | SRE_REVIEW table (small modules) |
| 74 | Responder key control: the responder chooses its ephemeral and ML-KEM inputs after the initiator's, so it can bias some key bits (book 5.1.1). It cannot force a reused key, since the initiator's input is fresh per handshake. Accepted; remedy would be a commitment in the INIT, which costs bytes | Low (accepted) | KEY_COMBINING_REVIEW K1; Boyd and Mathuria 5.1.1 |

## Unverified

Listed because the source itself says the item was not checked, or because it was read from code and not run.
No item was dropped for lacking a source.

- RFC 7296 INITIAL_CONTACT detail: not read beyond the retransmission rule (RFC7296_REVIEW, line 24).
- Ctrl+C traceback on the server: read from code, not run (OPERATIONS_REVIEW 9; item 38).
- SRE_REVIEW 11 item 7 says "server key rotation has no overlap". KEY_LIFECYCLE 5 gap 2 says the client side now overlaps. Which statement still holds for the server side was not checked (item 12).
- Web mock timing tests: not used because they are flaky (WEB_SECURITY_REVIEW ch. 6).

## Count

75 items in total: 23 protocol and crypto (2 added by the ML-KEM step), 31 operations and privileges (9 of them web mock items), 15 testing and verification, and 6 documentation.

## Status after the open-issues pass (2026-10-17)

The tables above are the list as it was. This section records what the pass did. Each "closed" item has a test; the file name is given.

**Closed in code, with tests**

| # | Change | Test |
|---|---|---|
| 3 | Runtime peer revocation from the peer file (done by another session, `peer_reload.py`) | `test_reload.py` |
| 6 | Session byte lifetime, 1 GiB of plaintext, then rekey (`REKEY_AFTER_BYTES`) | `test_lifetimes.py` |
| 13 | A refused INIT from a removed key is logged as "revoked", not "unknown" | `test_revocation_log.py` |
| 17 | The cookie secret rotates from the timers, not only on an INIT | `test_lifetimes.py` |
| 18 | A failed handshake names its step in the local log (wire unchanged) | `test_failure_stage.py` |
| 19 | Data is refused on a session older than three reject periods, between ticks | `test_lifetimes.py` |
| 25 | `vpn_keygen.py` prints private keys only with `--stdout`; no option is an error | `test_vpn.py` |
| 29 | Startup logs the peer file's SHA-256 and peer count | `test_ops_log.py` |
| 31 | Console lines carry a local timestamp (levels, log file and rotation are not done; see 33) | `test_ops_log.py` |
| 37 | Any unexpected exception in one datagram or timer run is logged by type and the loop keeps serving | `test_serve_resilience.py` |
| 38 | Ctrl+C prints "stopped (Ctrl+C)" and exits without a traceback | `test_serve_resilience.py` |
| 48 | Web sessions have an idle timeout (`VPN_SESSION_IDLE`, 900 s); a request resets it | `test_web.py` |
| 49 | Per-user session limit (`VPN_MAX_SESSIONS`, 5); the least recently used session is evicted | `test_web.py` |
| 63 | Recovery tested: restart then rekey with data; server rebuilt with no peers, then peer re-added | `test_recovery.py` |
| 65 | Concurrent wrong passwords still lock the account (race check) | `test_web.py` |
| 67 | `DATA_MIN_LEN` corrected to 36 (the measured keepalive size); the comment was wrong | `analysis` suite |
| 69 | THREAT_MODEL P-D1 now describes the per-datagram containment | doc |

**Accepted, with the reason**

| # | Reason |
|---|---|
| 5 | An identical INIT retransmission would reuse its timestamp, and the replay rule would reject it after a lost RESP. The deviation stays. |
| 7, 21 | Python cannot zero memory or control side channels in the interpreter. Platform limit. |
| 9 | Transport key derivation differs from Noise `Split()`. Stated deviation. |
| 20 | Traffic analysis is visible by design. Padding is 0 to 3 bytes. |
| 33 | No log file exists now; the operator controls redirection. |
| 35 | A cookie reply is about 72 bytes against a 1236-byte INIT. The printed "under load" line is not budgeted. |
| 36, 40 | Declared not needed, or declared out of scope for this prototype. |
| 46 | Lockout by username is a deliberate trade-off in the mock. |
| 47 | The server binds loopback only, so a per-IP limit would count every client as one address. |
| 51, 52 | Demo password printed and fake counters are intended for the mock. |

**Needs your decision** (design or policy; no change made)

| # | Decision needed |
|---|---|
| 1 | Global bandwidth cap for spoofed-source floods (the per-source budget is in place). What rate? |
| 2 | PSK per peer, or accept one shared PSK. |
| 4 | Per-message ratchet for forward secrecy. Large protocol change. |
| 8 | Wire version field. Protocol change, so existing peers must upgrade. |
| 10, 11, 12 | Backup server key, key-age records, and a rotation schedule. |
| 14, 30 | State file on by default, and integrity protection for it (how is the key managed?). |
| 15 | Entropy check for PSK and key files. A simple check is weak; what standard? |
| 16 | Freshness window for INIT timestamps (2 s in the model). Needs a clock-skew allowance. |
| 22, 23 | Rotation of the static ML-KEM key, and an independent audit. |
| 26 | Per-peer routes for TUN mode, so several peers can use it. |
| 27, 34, 42 | Zero-trust controls: client posture, per-role checks. |
| 28 | IPv6 outside the tunnel. Host-level policy. |
| 39 | Windows TUN (Wintun). Needs a driver and an installer decision. |
| 41 | Disclosure policy and contact. Needs your contact details. |
| 43 | Default `allowed_ips` in queue mode. A tighter default may break the demo. |
| 44 | TLS for the web mock. Needs a certificate decision. |
| 45 | Web audit log. Not built yet; log format is a decision. |
| 50 | Password change and recovery. A feature, not a fix. |
| 66 | Second account, to test isolation. Not built. |
| 70, 71 | SANS citations. The OCR text is not extracted in this folder. |
| 72 | TLS comparison. Documentation only; no TLS code was run. |
| 73 | Splitting `vpn_core.py`. Declared out of scope. |

**Needs hardware, a network, or an outside reviewer** (not done here)

| # | What is missing |
|---|---|
| 32 | Logging of rekey starts and silent drops is not built. Small, but needs an events path from `poll()`. |
| 53, 54, 55, 56 | A Linux kernel with TUN, a real network, and a real clock for timers. |
| 57 | Official Noise and WireGuard test vectors (earlier attempts returned 404). |
| 58 | RFC 4303 padding check, against the RFC text (not in this folder). |
| 59 | Coverage-guided fuzzing needs a fuzzing tool installed. |
| 60 | Static analysis. `pyflakes` install failed in this environment, so no lint was run. |
| 61, 62 | Independent review, and a formal proof. |
| 64 | Tag checks inside the `cryptography` library were not reviewed. |

## Status after round three (2026-10-17)

| # | Outcome |
|---|---|
| 1 | Global INIT budget that tunes itself: 200/s start, +25% when refusing, down to 2x admitted when quiet, between 50 and 2000/s. Tests in `test_global_budget.py` |
| 6 | INIT timestamp freshness window of 180 s against wall-clock time. Tests in `test_freshness.py` |
| 7 | External audit: not performed (I can't commission one). Scope document written: `tunnel\AUDIT_SCOPE.md` |
| 12 | IPv6 outside the tunnel: `tunnel\ipv6_guard.ps1` adds a firewall block rule (run it elevated) |
| 13 | Windows TUN backend on Wintun: `tunnel\tun_windows.py`, `--tun windows`. Fake-DLL tests in `test_tun_windows.py`. Real adapter not yet tested (needs an elevated shell: `python tun_windows.py --selftest`). The signed `wintun.dll` 0.14.1 (WireGuard LLC) is at `%LOCALAPPDATA%\ioessa-vpn\wintun\wintun.dll` |
| 15 | Optional HTTPS for the web mock (`VPN_TLS_CERT`, `VPN_TLS_KEY`) with HSTS. Tests in `test_web_tls.py` |
| 20 | SEC401 slides OCR'd with Tesseract 5.4 (247 pages). Combined text is in the scratchpad, not in the repository |
| 70 | Corrected: the course covers ICMP "fragmentation needed and DF flag set" (README updated) |
| 71 | Corrected: CDP appears in Module 3 and Module 5; IPsec at three places (OPERATIONS_REVIEW.md updated) |
| 2, 4, 5, 8, 14, 16, 17, 18 | Done in round two (see above) |
| 3, 9, 10, 11 | No code change, as decided: per-message ratchet not built (per-session rekey kept); no further entropy check; per-peer routes and zero-trust controls deferred |
| 22 | Splitting `vpn_core.py` deferred: worth doing once the protocol stops changing |

## Status after the core split and the elevated checks (2026-10-17)

| # | Outcome |
|---|---|
| 7 | Audit package prepared in `audit\`: frozen zip of `tunnel\` with a SHA-256 manifest, and a quote request. Still not commissioned (the user sends it) |
| 13 | Real Wintun self-test passed, elevated: adapter `ioessa-selftest` created, session started, closed, nothing left behind. Packet flow through a real adapter is still untested |
| 12 | `ipv6_guard.ps1` run elevated: `-Enable` adds one rule (`2000::/3`, `fc00::/7`, `fe80::/10`, `ff00::/8`), idempotent, `::1` still works; `-Disable` removes it. Left disabled. Blocking not observed: this network has no IPv6 internet |
| 22, 73 | Done: `vpn_core.py` split into `vpn_constants`, `vpn_errors`, `vpn_crypto`, `vpn_keyfiles`, `vpn_state`, `vpn_handshake`, `vpn_ip`, `vpn_transport`, `vpn_node` and `vpn_tun`. A pure move: no behaviour, wire format or error text changed. All callers and tests import from the new modules, and `vpn_core.py` is removed. See `SPLIT_PLAN.md` |