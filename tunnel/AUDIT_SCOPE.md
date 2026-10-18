# Audit scope: ioessa tunnel prototype (wire version 2)

Purpose: give an outside cryptographic and security auditor the scope, the specification, and the
evidence already gathered, so a review can start without a long handover. This is a prototype. Do not
use it to protect real traffic until an audit like this one has been done and its findings fixed.

## 1. What is in scope

| Component | Files | Why it matters |
|---|---|---|
| Handshake (Noise IK plus ML-KEM-768 hybrid, PSK per peer) | `vpn_handshake.py`: `make_initiation`, `consume_initiation`, `finish_initiation`, `make_response`, `consume_response`, `make_cookie_reply`, `consume_cookie`, `_init_chain`, `_mac1_key`, `_cookie_key`; `vpn_crypto.py`: `_kdf` | Establishes the session keys and authenticates both sides |
| Transport (ChaCha20-Poly1305, replay window, rekey) | `vpn_transport.py`: `seal_data`, `open_data`, `ReplayWindow`; `vpn_handshake.py`: `_transport_keys`; `vpn_node.py`: `Node.poll`, `Node._on_data` | Confidentiality, integrity and replay of data packets |
| Node logic (state, budgets, timers) | `vpn_node.py`: `Node.handle`, `_on_init`, `_on_resp`, `_on_cookie`, `_global_hs_budget`, `_source_budget` | DoS resistance and state handling |
| Key and state files | `vpn_keyfiles.py`: `load_static_private`, `load_kem_private`, `load_peer_entries`, `check_key_age`; `vpn_state.py`: `TimestampStore`, `state_key`; `vpn_keygen.py` | Key handling, integrity tag on the replay-state file |
| Server and client loops | `vpn_server.py`, `vpn_client.py`, `peer_reload.py` | Input handling and the runtime peer reload |

Out of scope (state these in the report): the Linux TUN backend `tun_linux.py` (not run on a kernel),
the web mock (`server.py`, `app.js`; a demonstration UI, not part of the tunnel), and the packet-analysis
toolkit `analysis/` (it reads captures; it is not in the protection path).

## 2. Specification

**Message layouts** (all little-endian; byte 0 type, byte 1 wire version = 2, bytes 2-3 zero):

| Message | Length | Fields |
|---|---|---|
| INIT (type 1) | 1236 | version, sender index, initiator ephemeral (32), ML-KEM ciphertext to responder static key (1088), encrypted initiator static key (48), encrypted TAI64N timestamp (28), mac1 (16), mac2 (16) |
| RESP (type 2) | 1180 | version, sender index, receiver index, responder ephemeral (32), ML-KEM ciphertext to initiator static key (1088), empty AEAD tag as key confirmation (16), mac1 (16), mac2 (16) |
| COOKIE (type 3) | 72 | version, receiver index, salt (32), encrypted cookie (32) |
| DATA (type 4) | 16 + body + 16 | version, receiver index, 64-bit counter, ChaCha20-Poly1305 ciphertext with padding, tag |

**Key schedule** (`Kdf` is HKDF-Extract-shaped over HMAC-BLAKE2s; the chaining key is the HMAC key):

1. Start: `ck = H(Construction)`, `h = H(ck, Identifier)`, `h = H(h, S_r)`, `h = H(h, K_r)` where `K_r` is the responder's ML-KEM key.
2. Initiator: `h = H(h, E_i)`; `ss, ct = Encaps(K_r)`; `h = H(h, ct)`; `ck = Kdf(ck, ss)`; `ck, k = Kdf(ck, DH(E_i, S_r))`; encrypt `S_i` under `k` with `h` as AAD; `h = H(h, enc_S_i)`; `ck = Kdf(ck, PSK)`; `ck, k = Kdf(ck, DH(S_i, S_r))`; encrypt timestamp under `k`; `h = H(h, enc_ts)`.
3. Responder, step 1 (`consume_initiation`): decapsulate `ct`, derive the same `ck`, decrypt `S_i`. It learns the peer identity here.
4. Responder, step 2 (`finish_initiation`): `ck = Kdf(ck, PSK_peer)`; `ck, k = Kdf(ck, DH(S_r, S_i))`; decrypt the timestamp. A wrong PSK fails here.
5. Responder: `E_r`; `ct_r = Encaps(K_i)`; `h = H(h, E_r)`; `h = H(h, ct_r)`; `ck = Kdf(ck, E_r)` when the PSK is non-empty (the PSK itself is mixed only once, in step 4; this extra
   mix of `E_r` is what `make_response` and `consume_response` do); `ck = Kdf(ck, DH(E_r, E_i))`; `ck = Kdf(ck, DH(E_r, S_i))`; `ck = Kdf(ck, ss_r)`; empty AEAD under `k` as key confirmation. Responder sends RESP.
6. Initiator (`consume_response`): repeats the same mixing order, checks the confirmation tag, and derives transport keys.
7. Transport keys: `k_i2r = Kdf(ck, "ioessa transport key I->R")` and `k_r2i = Kdf(ck, "ioessa transport key R->I")`.

`mac1 = MAC(H(label, receiver static public key), message)`; it is a filter, not authentication. `mac2`
is a cookie check used only under load. The derivation is written out in `KEY_COMBINING_REVIEW.md`.

**Timestamps.** INIT timestamps are TAI64N, strictly increasing per peer, and must be within 180 s of
the responder's wall clock (`FRESHNESS_WINDOW`). The responder keeps the last accepted timestamp per peer
and persists it in the state file, which carries an HMAC tag keyed from the responder's private key.

**Protection budgets.** A global INIT budget (self-tuning, 50 to 2000 per second) and a per-source budget
apply after mac1 and before any Diffie-Hellman work.

## 3. Claims the auditor should check

1. Mutual authentication: each side learns the other's static keys, and a responder that completes the
   handshake holds both the X25519 and the ML-KEM-768 private key. The reasoning is in `THREAT_MODEL.md`
   (H-X10, H-Q2).
2. Key confirmation in both directions (responder's tag, then the first data packet).
3. Freshness of the session keys: both sides contribute fresh ephemeral values.
4. Replay protection of INITs: freshness window, per-peer timestamp, state file. The model check
   (`model_check_init.py`) covers the timestamp rule only.
5. Forward secrecy per session (about 120 s), not per message. No post-compromise security.
6. Unknown key-share resistance: both static keys are bound into the chaining key and the transcript.
7. Failure behaviour: every handshake failure gets one generic wire reason, and the local log names the step.

## 4. Evidence already gathered (not a substitute for an audit)

| Evidence | Where | Result |
|---|---|---|
| Unit and integration tests | `tunnel\test_*.py` | 287 pass in the tunnel suite (run `python -m unittest` in `tunnel\`), 2026-10-17 |
| Mutation fuzzing of the datagram entry point | `tunnel\test_fuzz.py` | Passes; seed by `IOESSA_FUZZ_SEED` |
| Explicit-state model of the INIT timestamp rule | `tunnel\model_check_init.py` | Replay safety holds. A held-back INIT is accepted late only without the window |
| Key-combining review | `tunnel\KEY_COMBINING_REVIEW.md` | One accepted finding (K1: responder key control) |
| Threat model | `tunnel\THREAT_MODEL.md` | Covers the rows above |
| Side-channel review | `tunnel\SIDE_CHANNEL_REVIEW.md` | Secret comparisons are constant time |

## 5. Known open items the auditor should weigh

These are listed in `tunnel\OPEN_ISSUES.md`. The main ones for a handshake audit:

- K1: the responder chooses its ephemeral and ML-KEM inputs after the initiator's (key control, Low, accepted).
- Forward secrecy is per session only (item 4).
- The ML-KEM static key is not rotated automatically. An optional key-age limit exists (`--max-key-age-days`), off by default.
- The protocol is not interoperable with any other implementation, and there are no official test vectors (item 57).
- Python cannot zero secrets in memory (item 7).

## 6. Questions for the auditor

1. Is the hybrid combination (PSK mixed after the initiator static key; ML-KEM secret mixed as HKDF input)
   sound under the stated assumptions? Are the mixing order and labels correct?
2. Does the freshness window plus per-peer timestamp fully stop replay of INITs across restarts, given
   the state file is tagged but not rollback-protected?
3. Is the responder's key-confirmation tag sufficient, or does the protocol need an explicit initiator
   confirmation before the responder trusts data?
4. Any issue with using the static ML-KEM key for encapsulation to both directions?

## 7. Deliverables expected from an auditor

A written report with findings rated by severity, a fix recommendation for each, and a retest of the
fixes. Keep the report separate from the repository until the findings are fixed.

## 8. The version under audit

The project is not in version control, so the audited version is fixed by a package: a zip of `tunnel\`
(without `analysis\` and caches) plus `MANIFEST.sha256`, the SHA-256 of every file in it. Both are in the
project's `audit\` folder, named by date. Findings should cite file names and line numbers from that package.
A retest uses a new package with a new manifest.

Size of the scope in section 1, including comments and docstrings: about 1,600 lines for the protocol core
(`vpn_constants`, `vpn_errors`, `vpn_crypto`, `vpn_keyfiles`, `vpn_state`, `vpn_handshake`, `vpn_transport`,
`vpn_node`) and about 900 more for `vpn_server.py`, `vpn_client.py`, `vpn_keygen.py` and `peer_reload.py`.
`vpn_ip.py` and `vpn_tun.py` (80 lines) are helpers.

To run it: Python 3.13 and `cryptography` 50.0.2 (the versions used for the results above; Python 3.9+ and
a `cryptography` with ML-KEM support should work). In the unpacked folder: `python -m unittest` (tunnel
suite) and `python model_check_init.py`. No network or admin rights are needed.
