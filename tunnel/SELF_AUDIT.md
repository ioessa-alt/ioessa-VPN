# Self-audit (2026-10-21)

**This is a self-assessment by the authors, not an independent audit.** It follows the checklist in
`AUDIT_SCOPE.md` §3, §5 and §6 so that an outside auditor can check it. It does not replace one.

## Method

1. **Two fresh-eyes code reviews.** They saw only the code and the spec in `AUDIT_SCOPE.md` §2-3, and none
   of the earlier `*_REVIEW.md` files, so they were not anchored by them. One covered the handshake and crypto
   modules; the other covered parsing, DoS, state and reload. I re-checked S1-S8 and S10-S12 against the code
   (S1-S3 also with tests), corrected the reviewers' line numbers where they were wrong, and marked S9 unconfirmed.
   Findings that did not survive that check are listed at the end.
2. **Exhaustive bit-flip tests** (`test_self_audit.py`). Every bit of INIT and RESP before mac1 is flipped,
   mac1 is recomputed (an attacker knows the public key), and the message is passed to the handshake
   functions. Only flips in the 4 sender-index bytes are accepted; those bytes are chosen by the sender and
   are not in the transcript. Run with and without a PSK. No exception other than `HandshakeError` is raised.
3. **Tooling.**
   - `bandit -r .` (tests and `analysis\` excluded) reports only Low notes on `subprocess` use, all with
     fixed argument lists.
   - `pip-audit` finds no known vulnerabilities.
   - The crypto comes from `cryptography` 50.0.2 (OpenSSL): X25519, ML-KEM-768 and ChaCha20-Poly1305.
     There is no hand-written primitive. BLAKE2s and HMAC come from `hashlib` and `hmac`.
4. **Formal model:** the ProVerif results in `formal/FORMAL_MODEL.md`.

## Claims (`AUDIT_SCOPE.md` §3)

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 1 | Mutual authentication | Holds | ProVerif queries 3-5 are true in every finished variant. Bit-flip tests. `vpn_handshake.py` 104-210 |
| 2 | Key confirmation both ways | Holds | The responder's tag is checked in `consume_response`. The responder keeps its new session in `next` until the initiator's first data packet arrives (`vpn_node.py` `_promote`). Test: `test_claim2_*`. ProVerif query 4 |
| 3 | Fresh session keys | Holds | New `E_i` and `E_r` and two new encapsulations every run (`vpn_handshake.py` 112-115, 172-178) |
| 4 | INIT replay protection | Holds, with limits | `test_state.py` restart tests and `model_check_init.py`. Limits are S8 (state file deleted or rolled back), bounded by the 180 s freshness window |
| 5 | Forward secrecy per session | Holds classically; **fails post-quantum** | ProVerif `fs` is all true. `pq_fs` is false for queries 1-2 (S4) |
| 6 | Unknown key-share resistance | Holds | `S_r` and `K_r` are hashed at the start, and `S_i` through `enc_S_i` and the DH. `K_i` is bound only through `ss_r` (FIPS 203 hashes `H(ek)` into K), which is sound but implicit (I3) |
| 7 | Generic failure on the wire | Holds | `HandshakeError.reason` is always `HS_FAIL`, refusals are silent on the wire, and the step goes only to the local log. Timing differs between steps (I5) |

## Findings

Severity is for this prototype's threat model (`THREAT_MODEL.md`). "Fixed" means fixed in this pass, with a test.

| ID | Severity | Status | Finding | Where | Fix |
|---|---|---|---|---|---|
| S1 | Medium | **Fixed** | The Windows ACL check failed open. `icacls` prints specific rights comma-joined, as in `Everyone:(RD,REA,RA)`. That token matched no known right, so a private key readable by Everyone was accepted. Reproduced on a real file. | `vpn_keyfiles.py` `_parse_icacls` | Split groups on `,` and count every token except an inheritance flag, `(N)` or an integrity-label policy (`NW`, `NR`, `NX`). Tests: `test_s1_*`. Freshly generated key files are still accepted. A real `icacls` grant to Everyone is now refused |
| S2 | Medium | **Fixed** | A peer file holding per-peer PSKs was loaded with no permission check. | `vpn_keyfiles.py` `load_peer_entries` | Same check as a private key file when any entry has a PSK. Test: `test_s2_*`. Existing PSK peer files must now be owner-only (README) |
| S3 | Medium | **Fixed** | A non-ASCII byte in the peer file raised `UnicodeDecodeError` during a live reload. That was not caught, so it ended the server. | `peer_reload.py` `__call__` | Also catch `ValueError` and keep the current peers. Test: `test_s3_*` |
| S4 | Medium | Open (design) | No post-quantum forward secrecy. Both ML-KEM encapsulations go to static keys. | `vpn_handshake.py` 115, 178. ProVerif `pq_fs` | Add an ephemeral ML-KEM key per handshake, or state that the claim is classical-only. Found by ProVerif (`FORMAL_MODEL.md` finding 1); AUDIT_SCOPE question 4 |
| S5 | Medium | Open | The global INIT budget is spent before the per-source check. One real address with a valid cookie can use up the global budget and lock out other peers. | `vpn_node.py` `_on_init` (global, then source) | Check the per-source budget first, or refund the global token when the per-source check fails |
| S6 | Medium | Open | Under load, every INIT with a valid mac1 adds an unthrottled "cookie reply" log line. `RejectCounter` passes every line through, so this allows a log or stdout flood. | `vpn_node.py` `_on_init` | Route it through `_refuse` (rate-limited), or count it instead |
| S7 | Low | Open | An `OSError` from `sock.sendto` (for example EPERM from a firewall, or ENETUNREACH) is not caught in the serve loops, so it ends the process. | `vpn_server.py` 116, 131, 138, 155, 197, 219, 225; `vpn_client.py` 60, 119 | Catch `OSError` around each send and log it |
| S8 | Low | Open | A deleted state file silently resets INIT replay protection, and an older tagged file can be restored. Bounded by the 180 s freshness window. | `vpn_state.py` 92-93 | Write a tagged empty file on first run and refuse a missing file afterwards, or warn loudly. Add a counter to the tag |
| S9 | Low | Unconfirmed (Linux only) | With `--drop-to`, the state directory is created as root, so later state writes may fail and every INIT is refused. Fails closed. | `vpn_server.py` 280-283, `tun_linux.py` `drop_privileges` | Change the directory's owner before the drop, or test writing at startup |
| S10 | Low | Open | `apply()` removes peers before adding the new ones. If `add_peer` raises, the reload is left half-applied. | `peer_reload.py` `apply` | Validate every entry first, then apply |
| S11 | Low | Open | The Windows ACL check compares principals by name only, so `OTHERPC\alice` passes as `alice`. | `vpn_keyfiles.py` `_parse_icacls` | Compare SIDs |
| S12 | Low | Open | A stale `next` session stays after a RESP until it expires (at most one per peer). | `vpn_node.py` `_on_resp` | Clear `peer.next` there |

### Info

- I1: `CONSTRUCTION_PSK` (`vpn_constants.py:80`) is unused. Its comment says "used when a PSK is set", which is wrong. The code always uses `CONSTRUCTION`, as the spec says.
- I2: The 4-byte header is not hashed into `h`. Type and version are enforced by the exact-shape check, and the bit-flip test confirms changed header bytes are refused.
- I3: `K_i` is not hashed into `h` (see claim 6).
- I4: Data is accepted for up to 3 x `reject_after` (`vpn_node.py:542`). This matches WireGuard, and sending stops at `reject_after`.
- I5: The timing of a wrong-key failure (step 1) and a wrong-PSK failure (step 4) differs.
- I6: There is no per-peer destination ACL inside the tunnel. Inner source addresses are checked.
- I7: The POSIX key check does not verify the file owner. There is a gap between the mode check and the `open()`.
- I8: `make_response` accepts an `InitInfo` that has not been through `finish_initiation`. That fails safe, because the initiator's tag check fails.
- I9: A crash between `mkstemp` and `os.replace` leaves a `.tmp` file behind.

### Raised but not confirmed

- A duplicated RESP reusing nonces: not a problem. `_on_resp` drops the pending state before it creates the session, so a second RESP is ignored.
- A parser crash on malformed datagrams: none found. This is covered by `test_fuzz.py` and the bit-flip tests.
- Amplification: none. COOKIE (72) and RESP (1180) are both smaller than INIT (1236).

## Questions (`AUDIT_SCOPE.md` §6)

1. **Hybrid combination.** Sound under the stated assumptions. ProVerif finds no attack on data secrecy
   with ML-KEM broken (`kem_broken` queries 1-2; queries 3-5 still running) or with all keys stolen
   afterwards (`fs`). The mixing order and labels match §2 (fresh-eyes review).
2. **INIT replay across restarts.** Not fully. Replay is bounded by the 180 s freshness window, but a
   deleted or rolled-back state file reopens that window (S8).
3. **Responder key confirmation.** It is enough, because the responder does not send data before the
   initiator's first data packet confirms the keys (claim 2).
4. **Static ML-KEM in both directions.** Yes, there is an issue: there is no post-quantum forward secrecy (S4).

## Retest

`python -m unittest test_self_audit` passes, along with the suites that touch the fixed code. Open items stay
in this file until they are fixed; a fix needs a test and a new audit package (`AUDIT_SCOPE.md` §8).
