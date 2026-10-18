# Randomness review

Date: 2026-10-16. Scope: every randomness source in `tunnel\` (production modules `vpn_core.py`, `vpn_server.py`, `vpn_client.py`, `vpn_keygen.py`, `tun_linux.py`, plus the test files). `analysis\` is out of scope and was not edited.
Reference: *Cryptography Engineering*, Ferguson, Schneier, Kohno, ch. 9 "Generating Randomness" (sections 9.2 to 9.6 read).

## Summary

- All production randomness comes from the OS CSPRNG (`os.urandom`), the `secrets` module, or `cryptography`'s `X25519PrivateKey.generate()`, which uses the OS RNG underneath.
- No production module imports `random`. No seed is taken from time, PID or any other predictable value.
- The tunnel does not write any key or generator state to disk. There is no seed file.
- No custom generator, entropy pool or reseeding logic exists, and none is recommended.
- Two findings: the optional PSK check accepts an all-zero key (verified), and in-memory session state would be duplicated by a VM snapshot restore or a process fork (reasoned, not tested).

## 1. Inventory

Production code, every randomness call site (the AST test in `test_randomness.py` enforces this list):

| # | Location | Call | Used for | Kind |
|---|---|---|---|---|
| 1 | `vpn_core.py:640` (`Node.__init__`) | `os.urandom(32)` | Initial cookie secret R_m | MAC key |
| 2 | `vpn_core.py:663` (`_cookie_secrets`) | `os.urandom(32)` | Cookie secret rotation (every `COOKIE_SECRET_TIME`) | MAC key |
| 3 | `vpn_core.py:457` (`make_cookie_reply`) | `os.urandom(32)` | Salt for the cookie-reply encryption key, one per reply | Salt |
| 4 | `vpn_core.py:657` (`_new_index`) | `secrets.randbelow(2**32 - 1) + 1` | Sender and session indices, checked for collisions | Identifier |
| 5 | `vpn_core.py:368` (`make_initiation`) | `X25519PrivateKey.generate()` | Initiator ephemeral key | Ephemeral key |
| 6 | `vpn_core.py:410` (`make_response`) | `X25519PrivateKey.generate()` | Responder ephemeral key | Ephemeral key |
| 7 | `vpn_core.py:272` (`generate_keypair`) | `X25519PrivateKey.generate()` | Static keypair generation | Long-term key |
| 8 | `vpn_core.py:267` (`new_private_key`) | `X25519PrivateKey.generate()` | Wrapper around the same call | Long-term key |
| 9 | `vpn_core.py:201` (`_is_low_order`) | `X25519PrivateKey.generate()` | Throwaway key for the low-order check, never used as a secret | Not a secret |
| 10 | `vpn_keygen.py:19` | `generate_keypair()` (calls #7) | Operator's static keypair; `--out` writes with `O_EXCL`, mode 0600 | Long-term key |

Not randomness, checked and found fine:

| Location | Value | Note |
|---|---|---|
| `vpn_core.py:83`, `:489` | `ZERO_NONCE`; data nonce = 4 zero bytes + 64-bit counter | Deterministic nonces. Safe because each key is used once (CRYPTO_REVIEW F4). No random nonces anywhere. |
| `vpn_core.py:503-504` | Padding `1, 2, 3, ...` | Deterministic by design (from the ESP prototype), not random. Encrypted, so predictable padding is not a leak. |
| `vpn_core.py:732` | `time.time_ns()` in `_tai64n` | Handshake timestamp for replay protection. Wall clock, not a seed. |
| `vpn_core.py:630`, `vpn_client.py`, `vpn_server.py` | `time.monotonic` | Timers only. |

Test-only randomness (not shipped): `test_vpn.py` `os.urandom` at lines 33, 72, 73, 128, 384, 387, 388; `time.time_ns` at 526, 534.

Flags:
- `random` module in production: none. The only use in `tunnel\` is `analysis\slow_network.py` (`random.Random(seed)`, for simulated packet loss). It is not key material and it is out of scope.
- Time or PID as a seed: none. `os.getpid` is not used.
- `random` used by `test_vpn.py`: none.

## 2. Fortuna properties and whether they apply

The book says (section 9.3) that in practice you are best off using a cryptographic PRNG from a well-accepted library, and Fortuna is for illustration. This tunnel does that.

| Fortuna property (book section) | Applies here? | Reasoning |
|---|---|---|
| Seed with real entropy before use (9.3, 9.6.6) | Yes, but the OS does it | The tunnel only calls the OS. Whether the OS RNG is seeded when the tunnel starts is the OS's job. Not verified on the target host (see section 6). |
| Never use the generator before it has enough entropy; early boot is low entropy (9.2, 9.6.6) | Only through the OS | If the tunnel starts before the OS RNG is initialized, the keys it makes at startup would be weak. The repo has no service unit, so start ordering is not checked. |
| Pool many entropy sources, with no estimator (9.5.1, 9.5.2) | No | Entirely the OS's job. A custom pool would add risk and no benefit. |
| Bounded reseeding, pool 0 threshold, 100 ms rule (9.5.2) | No | The tunnel never reseeds a generator. Its random values are one-shot draws. |
| Forward security of generator output: rekey after each request (9.4) | Partly, by analogy | The tunnel's forward secrecy comes from fresh ephemeral DH per session, not from a PRNG rekey. Session granularity only, with no ratchet (CRYPTO_REVIEW F5). |
| Seed file, its update, and backup or restore duplication (9.6.1 to 9.6.5) | No, because there is no seed file | No key or generator state is written to disk. Disk backup and restore cannot duplicate session state. |
| Fork and VM snapshot duplicate generator state (9.6.4) | Yes, for in-memory session state | See section 4. |
| Attacker-controlled events and source numbering (9.5.1) | No | No event pool exists. |
| Entropy estimators are unreliable (9.2) | No | No estimator is used. |

Conclusion: a custom Fortuna-style generator is not needed. Writing one would duplicate the OS CSPRNG and would add entropy-pooling and reseeding code, which is where the book's own warnings apply. I recommend against it. The one property that matters for this design, that nothing is duplicated or reused, is a process-lifetime issue and is covered in section 4.

## 3. Tests added

New file: `tunnel\test_randomness.py`. 18 tests, all passing.

- Source scans (ast-based, so comments and strings do not affect them): `test_no_random_module_in_production_code`, `test_no_random_names_referenced`, `test_randomness_calls_are_exactly_the_inventory` (the set of randomness calls must equal `{os.urandom, secrets.randbelow, X25519PrivateKey.generate}`), `test_no_fork_or_multiprocessing`.
- Sizes: `test_static_keypair_is_32_bytes`, `test_cookie_secret_is_32_nonzero_bytes`, `test_cookie_salt_is_32_bytes`, `test_session_transport_keys_are_32_bytes`, `test_psk_shorter_than_32_bytes_is_refused`, `test_psk_of_32_bytes_is_accepted`, `test_session_index_is_nonzero_32_bit`.
- Cookie secret: `test_rotation_never_reuses_a_secret` (five rotations, no repeats, previous = the one just retired), `test_no_rotation_before_the_interval`, `test_two_nodes_get_different_cookie_secrets`.
- Behaviour: `test_cookie_salt_comes_from_os_urandom` (spy on `os.urandom`), `test_key_generation_ignores_the_random_module` (seeding `random` does not repeat keys), `test_cookie_salt_ignores_the_random_module`, `test_handshakes_do_not_repeat_keys`.

Mutation check on a scratch copy (not the real tree): appending `import random` and a `random.getrandbits` call to `vpn_core.py` made three scan tests fail. So the scans do detect the problem they target.

Limits of the scans: they match direct calls named `urandom`, `randbelow`, `generate` and similar on a plain name. They do not catch an aliased import (`from os import urandom as u`), `getattr` tricks, or a call through a variable. Those would show up in review, not in the test.

Full suite: `python -m unittest` from `tunnel\` gives 110 tests, OK (92 before, plus 18).

## 4. Fork and snapshot

- The prototype is single-process and single-threaded. `vpn_server.py:94` says one thread drives `Node`, which is not thread safe. No `os.fork`, `multiprocessing` or `threading` appears in production code (checked by grep and by a test).
- Nothing about key or session state is written to disk. A disk restore therefore cannot re-create an old session.
- In-memory state does survive a fork or a VM snapshot restore: the session `send_key`, `send_counter` and replay window, and the cookie secrets. If two copies of the process both send on the same session, the same (key, nonce) pair encrypts different plaintexts. For ChaCha20-Poly1305 that breaks confidentiality and integrity for that session. This is reasoned from the code, not run.
- Nothing in the code handles this. Mitigation options, none implemented: (a) detect a restore or fork (boot ID, or a clock jump larger than some bound) and drop all sessions, forcing a new handshake; (b) on POSIX, `os.register_at_fork` to clear sessions in the child; (c) for a multi-process design, give each process its own sessions and never share one session across processes; (d) operators should not run two copies of a snapshot.

## 5. Verified and not verified

Verified (run in this session):
- Inventory by grep and AST, matching the list in section 1.
- The 18 new tests and the full suite: 110 OK.
- The scans fail when `random` is injected into a scratch copy.
- `load_psk` accepts a 32-byte key of all zeros (ran `load_psk` with `IOESSA_VPN_PSK = "00" * 32`; it returned 32 zero bytes).
- No fork, multiprocessing or threading in production code.
- CRYPTO_REVIEW.md F8 is consistent with the code.

Not verified:
- Which randomness backend `os.urandom` uses on this machine, and whether it blocks or returns early at boot on the target OS.
- Start ordering of the tunnel service relative to OS RNG initialization (no service files in the repo).
- The snapshot and fork consequences in section 4. They were not reproduced.
- Entropy quality of an operator-supplied PSK or key file. Only length is checked.

## 6. Remaining risks and recommendations

1. **Stale, fixed later:** `load_psk` now refuses an all-zero PSK (`vpn_core.py` lines 362-363; `test_all_zero_psk_is_rejected`, test_fixes.py). The original finding follows. All-zero PSK accepted. `load_psk` checks length only. An operator who sets `00` * 32 gets a PSK that is public. Recommend rejecting an all-zero or obviously low-entropy PSK, and pointing operators to a generator. Not changed here: it is a behaviour change and the brief said to keep edits small.
2. Session state duplicated by fork or snapshot restore (section 4). Recommend a restore check plus session clearing, when the tunnel is ever deployed on VMs or with snapshots.
3. Early boot. Recommend the service start after the OS RNG is ready. Check this with the service definition when one exists.
4. Cookie secret rotation is lazy: `_cookie_secrets` runs only when an INIT arrives. Not a randomness defect. The secret is simply older when it rotates.
5. Timestamps are wall-clock `time_ns()` values (TAI64N). Not a randomness issue, but a clock set backwards would weaken replay protection. Out of scope here.
