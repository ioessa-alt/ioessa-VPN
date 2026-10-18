# Crypto review: tunnel/vpn_core.py against *Real-World Cryptography* (Wong)

Date: 2026-10-16. Scope: `vpn_core.py`, `vpn_keygen.py`, and the key handling in `vpn_client.py` and `vpn_server.py`. Not reviewed: `tun_linux.py`, `analysis\`.

Book passages read (page numbers from the extracted text): ch. 4 nonce counters and birthday bound (pp. 79-80); ch. 5 small subgroup attacks and invalid curves (pp. 105-107); ch. 8 HKDF (pp. 164-168, located by grep only) and the CSPRNG/unpredictability passages (grep only); ch. 9-10 forward secrecy and the Signal symmetric and DH ratchets (grep, short reads); ch. 13 zeroization (p. 284). Chapters 2 and 3 were located but not read in full; the hash and MAC points below rest on the code and the RFCs, not on the book text.

## Summary

| # | Severity | Finding | Status |
|---|---|---|---|
| F1 | Low | Low-order peer public keys accepted from config; the first `initiate()` raised an uncaught `HandshakeError` and crashed the poll loop | Fixed, tested. Verified |
| F2 | Info | BLAKE2s, keyed BLAKE2s, HMAC-BLAKE2s and Kdf checked against official and textbook definitions | Verified for the primitives. Official Noise and WireGuard handshake vectors: not verified (not obtainable) |
| F3 | Info | Transport keys come from two label-KDF calls on `ck`, not Noise `Split()` | Not changed (wire-level deviation). Secure as written |
| F4 | Info | Nonce construction, key uniqueness, and rekey limit | Verified by reading and existing tests. No defect found |
| F5 | Medium (design) | Forward secrecy is per session (about 120 s), not per message; no ratchet; previous-session keys linger up to 540 s | Documented. No ratchet added (no concrete gap against the stated design) |
| F6 | Medium (limit) | Keys cannot be wiped from Python memory | Documented. No wiping claimed |
| F7 | Low | Key storage: keygen prints the private key without `--out`; env vars readable by same-user processes; Windows ignores the 0600 mode; the key-file mode is not checked on load | Documented, not changed |
| F8 | Info | Randomness and key logging | Verified: no defect found |
| F9 | Low (residual) | INIT replay state (per-peer timestamp) is lost on restart | Superseded by the state-file fix: kept on disk with `--state-file` (see section F9, `test_state.py`). Without the file, the old behaviour still applies |

## F1. Low-order peer public keys accepted from config (Ch. 5, small subgroup attacks)

- **Where:** `public_key_from_b64` and `Node.add_peer`. Both checked only for an all-zero key.
- **Problem:** A configured key such as the u-coordinate `1` (`01 00 .. 00`), which is a small-order X25519 point, passed validation. The first `initiate()` then called `_dh()`, which raised `HandshakeError`. Nothing in `vpn_client.py` or `vpn_server.py` catches it around `initiate()` or `poll()`, so the process died. Remote input was not affected: `consume_initiation` and `consume_response` already catch the error.
- **Reproduced before the fix:** `public_key_from_b64` accepted `u=1`, and `Node.initiate()` raised `HandshakeError: handshake failed`.
- **Change:** Added `_is_low_order(pub)`, which asks X25519 for an exchange with a fresh key and treats `ValueError` (the all-zero output) as low order. Both config paths now use it. The message in `public_key_from_b64` changed accordingly. `THREAT_MODEL.md` K-T2 was updated to match.
- **Tests:** `CryptoReviewTests.test_low_order_points_refused_in_config` checks seven small-order encodings: `u=0`, `u=1`, two order-8 points, and the non-canonical `p-1`, `p`, `p+1`. `test_valid_public_keys_still_accepted` checks that random keys still pass.
- **Verified:** Yes. All seven encodings are rejected by the library, and the tests pass.

## F2. Test vectors (Ch. 2, 3, 5)

| Check | Source | Result |
|---|---|---|
| BLAKE2s-256("abc") | RFC 7693 Appendix B (final state h[0..7], little-endian bytes) | Pass (`test_blake2s_rfc7693_abc`) |
| Keyed BLAKE2s-256, key 00..1f, inputs of length 0, 1, 2, 64 | Official `blake2s-kat.txt` from github.com/BLAKE2/BLAKE2, downloaded and checked | Pass (`test_blake2s_keyed_official_kat`). These are the `_mac` path used for mac1, mac2 and the cookie |
| HMAC-BLAKE2s equals the RFC 2104 formula with block size 64 | Textbook formula written in the test, plus `hashlib.blake2s().block_size == 64` | Pass (`test_hmac_blake2s_is_rfc2104_hmac`) |
| `_kdf` equals Noise `HKDF(ck, ikm, 2)` | Noise spec definition (temp = HMAC(ck, ikm); o1 = HMAC(temp, 0x01); o2 = HMAC(temp, o1 \|\| 0x02)) | Pass (`test_kdf_is_noise_hkdf_with_two_outputs`). Also checked against random inputs in a scratch script (100 cases) |
| Official Noise test vectors (e.g. cacophony) | Tried github raw URLs under rweather/noise-c, noiseprotocol, WireGuard/wireguard-go | **Not obtained (404 at every URL tried). Not verified.** |
| WireGuard test vectors | Not located | **Not verified** |

Important: the handshake is not standard Noise. It uses the WireGuard identifier, WireGuard-style mac1 and cookie keys, a PSK placed in the chain before the ephemeral (not Noise's `IKpsk2` placement), and label-based transport keys. Standard Noise vectors would not apply to it directly. Pinning a full handshake transcript would need vectors from this construction, and none were available. No claim is made that the full handshake matches any official vector.

## F3. Transport key derivation (Ch. 8, HKDF; Noise Split)

- `_transport_keys` derives `k_i2r = Kdf(ck, "ioessa transport key I->R")` and `k_r2i` the same way. Noise's `Split()` would use `HKDF(ck, zerolen, 2)`.
- Both keys are PRF outputs of `ck` on different inputs, so they are independent and differ by direction. This is sound.
- Not changed. Changing it would change the wire keys, and the constraints say not to change the wire format without a real bug.

## F4. Nonces, key uniqueness and rekey limits (Ch. 3-4)

- **Transport:** nonce is 4 zero bytes followed by the 64-bit little-endian counter (`_data_nonce`). Each direction has its own key (`k_i2r` and `k_r2i`), so a (key, nonce) pair cannot repeat across directions. Existing test checks `send_key != recv_key` and that the two peers' keys mirror each other (`test_vpn.py` around lines 112-114).
- **Counter:** starts at 1 (`seal_data` increments before use). `seal_data` refuses when `send_counter >= limit`, and `limit = 2^32 - 1024`, so the 32-bit space cannot wrap. Existing tests cover `RekeyRequired` at the limit and the constant relationship (`test_vpn.py` around lines 218, 615 and 643).
- **Crash recovery:** the book's warning about counter state after a crash (ch. 4, p. 80) does not apply. A restart creates new session keys from new ephemerals, so a counter reset never reuses a key.
- **Handshake AEAD:** `ZERO_NONCE` is used everywhere in the handshake. This is safe only because each AEAD key is used once. Each key comes from a new chaining step (`ck` changes after every DH), and the cookie key includes a fresh 32-byte salt. Checked by reading every `_aead_seal` and `_aead_open` call.
- **Verified:** Yes, by reading and existing tests. No new defect found.

## F5. Forward secrecy and the rekey design (Ch. 9-10)

- **What is provided:** Transport keys mix in DH(ephemeral, ephemeral) (`ee`) on both sides, so they do not depend only on the static keys. A later compromise of the static keys does not reveal past transport keys, as long as the ephemeral private keys were discarded. This is forward secrecy at session granularity.
- **Granularity:** A session lasts up to `REKEY_AFTER_TIME` (120 s), the count limit (about 4 billion packets, far beyond what 120 s carries), and `REJECT_AFTER_TIME` (180 s). A compromised session key exposes that session's traffic up to its end, and the book's per-message forward secrecy (symmetric ratchet, ch. 10) is not provided.
- **Previous session:** the previous session's keys stay in memory until `_expire` removes them after `3 * REJECT_AFTER_TIME` (540 s), as the paper specifies (VI-C). A memory read in that window exposes the previous session's traffic. This is documented, not changed.
- **Post-compromise security:** a passive attacker who captures session keys is locked out at the next rekey, since the new session's keys come from fresh DH. An active attacker holding static keys can still impersonate a peer, so PCS holds against passive capture only.
- **Decision:** No ratchet was added. There is no concrete gap against the design as stated. What the prototype provides is: per-session forward secrecy with about 120 s granularity, and no per-message forward secrecy and no PCS against active attackers. This is stated here rather than implied by the README, which makes no forward secrecy claim.

## F6. Memory wiping (Ch. 13, zeroization, p. 284)

- Python `bytes` are immutable and copied freely, and the GC does not zero freed memory. Session keys, `ck`, `h`, and the ephemeral private keys can therefore persist in memory after they are dropped, and the code cannot prevent it.
- The code does not claim to wipe anything. The `repr=False` on key fields only prevents them from being printed.
- **Not fixed. Platform limit.** Stronger handling needs native code, and the constraints forbid new crypto code.

## F7. Key storage (Ch. 8, Ch. 13)

- `vpn_keygen.py` with `--out` creates the private key with `O_EXCL` and mode 0600, and the public key with `O_EXCL`. On Windows the mode is ignored, so the file inherits the directory ACL.
- Without `--out`, `vpn_keygen.py` prints the private key to stdout. That lands in terminal scrollback and shell history. This is the documented behavior ("copy them into env vars"). Not changed, but users should prefer `--out`.
- `IOESSA_VPN_PRIVATE_KEY` is visible to other processes of the same user, and to child processes. THREAT_MODEL K-I2 already accepts this.
- `load_static_private` does not check the key file's permissions on load. A world-readable file is accepted silently on POSIX.
- No hardware or TPM support was built (per the task). The book's HSM and zeroization points (ch. 13) are not met by a software prototype.
- **Verified:** The code paths above were read. The Windows and POSIX behavior was not run on a POSIX host.

## F8. Randomness and key logging (Ch. 8)

- Randomness: X25519 key generation uses the library's OS-backed RNG. The cookie secret and the cookie salt use `os.urandom`. Sender indices use `secrets.randbelow`. The tunnel code does not import `random`. `analysis\slow_network.py` uses `random` for a simulation, not for keys, and was not changed.
- TAI64N timestamps use the wall clock. They are not secret and only need to increase per peer, which `next_timestamp` ensures.
- Logging: `act.events` strings hold addresses and fixed reasons (`HS_FAIL`, `ESPError` labels). `InitState`, `InitInfo` and `Session` mark key fields `repr=False`. `describe` prints payload bytes only on request. Exceptions from key loading contain no key material.
- **Verified:** Yes, by reading and by the existing test that key material is not in `repr(sa)`.

## F9. Residual replay state (not covered by the book passages read)

- **Superseded by the state-file fix.** `--state-file` (or `IOESSA_VPN_STATE_FILE`) keeps the greatest INIT timestamp per peer on disk, written before the RESP is sent. It is reloaded at start, and a malformed file stops the server. Tests: `test_state.py`. The text below describes the behaviour without `--state-file`, which is still the default.
- The responder remembers the greatest INIT timestamp per peer in memory. A restart clears it, so an old INIT can be accepted again. The responder then creates a `next` session that waits for data, which only the real initiator's keys can use, so this gives an attacker nothing. This matches the WireGuard reference design. Not changed. Since the endpoint fix, an accepted replayed INIT also no longer moves the peer's endpoint (`test_hardening.py`).

## F10. Post-quantum authentication and confidentiality (static ML-KEM-768)

- **What changed.** Each node has a long-term ML-KEM-768 key (FIPS 203, from cryptography's mlkem module, OpenSSL underneath) next to its X25519 key. The handshake encapsulates to the responder's static ML-KEM key in INIT, and the responder encapsulates back to the initiator's static ML-KEM key in RESP. Both shared secrets are mixed into the chaining key, so the transport keys depend on them.
- **Authentication.** Impersonating a peer needs both its X25519 private key and its ML-KEM private key. The responder's identity is shown by opening INIT, which needs its ML-KEM secret. The initiator's identity is shown by its first data packet, which needs the key that only it can derive from the RESP ciphertext. Tests: 	est_leaked_server_x25519_key_alone_cannot_read_an_initiation, 	est_leaked_client_x25519_key_alone_gives_no_session.
- **Confidentiality.** A recorded handshake cannot be decrypted by a quantum computer that breaks X25519, because the transport keys also depend on ML-KEM-768 secrets that are never sent in the clear. This is the "harvest now, decrypt later" protection.
- **Not "unbreakable".** No construction is. This design assumes ML-KEM-768 holds (NIST FIPS 203, August 2024), that the cryptography build is correct, and that the handshake code is correct. None of it has been audited, and it has not been checked against an independent implementation.
- **Forward secrecy.** The ML-KEM keys are static, so a stolen ML-KEM key exposes the sessions it protected. X25519 ephemeral keys still give forward secrecy against a stolen X25519 key, and that is the only protection against a stolen ML-KEM key. Rotate the static keys (pn_keygen.py) to limit this.
- **Sizes.** INIT 1236 bytes (was 148), RESP 1180 bytes (was 92). Each fits one 1500-byte MTU datagram with IP and UDP headers.
- **Key checks.** A peer's ML-KEM key is checked by MLKEM768PublicKey.from_public_bytes when it is configured (dd_peer, load_peer_publics). A malformed key is refused. A peer with no ML-KEM key is never sent an INIT (fail closed).
- **Profiles.** --profile standard rotates session keys every 120 s, the paper's timers. --profile strict rotates every 30 s and refuses to send after 45 s, so a stolen session key exposes less traffic. The handshake costs about 0.36 ms of CPU (ML-KEM encapsulation about 42 µs, decapsulation about 61 µs), so strict adds about one handshake per 30 s and very little CPU. The toggle changes exposure, not speed.
- **Wire compatibility.** Peers built before this change cannot complete a handshake with this build. Both ends must be updated together, and each side needs the other's <X25519>:<ML-KEM> entry.
- **Tests.** 	est_vpn.py PostQuantumTests, and the attack tests in ProtocolAttackTests. The model of the INIT rule and the loss check are described in README.md.
## Other notes

- The optional PSK is placed in the chain before the ephemeral, not per Noise `IKpsk2`. It is not a weakness, but it is not standard. Documented.
- The `cryptography` package provides X25519 and ChaCha20-Poly1305 only. BLAKE2s, HMAC and Kdf are the local construction above, backed by hashlib and hmac. No cipher or MAC was implemented.

## Changed files

- `vpn_core.py`: `_is_low_order` added; `public_key_from_b64` and `Node.add_peer` use it.
- `test_vpn.py`: imports `hashlib` and `hmac`; new `CryptoReviewTests` class (6 tests) with `LOW_ORDER_PUBLIC`.
- `THREAT_MODEL.md`: K-T2 row updated for the low-order rule.
- `CRYPTO_REVIEW.md`: this file.
- Wire format changed in the post-quantum pass (F10). Earlier builds cannot talk to this one.

## Remaining risks

1. Official Noise and WireGuard handshake vectors are not checked. The handshake is verified only by its unit tests, not by an external transcript.
2. Forward secrecy is per session (about 120 s), with no per-message ratchet and no PCS against active attackers.
3. Memory cannot be wiped from Python.
4. Key storage relies on OS ACLs and the operator; Windows ignores the 0600 mode.
5. The transport key derivation differs from Noise `Split()`. This is a deviation from the spec, not a known weakness.
