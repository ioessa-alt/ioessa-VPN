# Security engineering review: tunnel prototype against Anderson, *Security Engineering* (3rd ed.)

Scope: `tunnel\` (vpn_core.py, vpn_server.py, vpn_client.py, vpn_keygen.py, tun_linux.py). The
earlier reviews (CRYPTO, SIDE_CHANNEL, RANDOMNESS, NETWORK_SECURITY, OPERATIONS, KEY_LIFECYCLE) and
THREAT_MODEL.md are not repeated here. Where a claim is already there, this file gives the test or
the new finding only.

Status key: **Defended** = in code and checked by a named test. **Partly** = in code, with a stated
gap. **Open** = not defended, and not accepted as a design choice. **Accept** = a design decision
recorded in THREAT_MODEL.md. **N/A** = the attack needs a feature this design does not have.

## Book passages read

| Chapter | What was read | Use in this review |
|---|---|---|
| ch02 | Section framing only (capabilities of the opponent) | Opponent model. No finding depends on it |
| ch04 | 4.3.3 MIG-in-the-middle, 4.3.4 Reflection, 4.4 Manipulating the message, 4.5, 4.6 Chosen protocol attacks, 4.7.3 Needham-Schroeder, 4.8 headings | Protocol attack classes |
| ch05 | Section headings and a keyword grep | Crypto claims are checked against the code, not the text |
| ch19 | 19.3.3, 19.4.1 timing analysis, headings for 19.4.3 to 19.4.5 | Side channels |
| ch20 | 20.5.1 xor-to-null-key attack | Implementation pitfalls. Other sections are not applicable here |
| ch21 | 21.2 intro, 21.2.5, 21.4.1.4 ingress and egress filtering, 21.5.2.4 VPNs | Network defence |
| ch27 | 27.5.3 steps (requirements to release), 27.5.7 headings | Process |
| ch28 | 28.3.2 hostile review, 28.5 sustainability | Assurance |

Note: the extracted ch04 text has no sections named "parallel sessions", "interleaving" or "type
confusion". Those classes were checked against the replay, reflection and message-manipulation
passages above, and each one has its own test below.

## 1. Chapter 4: protocol attacks (handshake, RESP, DATA)

The handshake is Noise IK over X25519, ChaCha20-Poly1305 and BLAKE2s, with cookies and TAI64N
timestamps. Names below are functions in `vpn_core.py` unless a file is given.

| Attack class (book passage) | Claim | Code location | Status | Test |
|---|---|---|---|---|
| Replay of INIT (4.7.3, freshness) | A replayed INIT is refused. Each INIT carries an encrypted TAI64N timestamp, and it must be greater than the last one from that peer | `Node._on_init`, `Peer.last_init_ts`, `Peer.next_timestamp` | Defended. Across restart: only with `--state-file` (state file added; CRYPTO F9 superseded) | `test_replayed_initiation_rejected`, `test_old_timestamp_rejected`, `test_timestamps_strictly_increase_per_peer` |
| Replay of RESP | A RESP is accepted only while its INIT is pending. A second copy after tunnel-up changes nothing | `Node._on_resp`, `consume_response` | Defended | `test_replayed_response_after_tunnel_up_changes_nothing` (new) |
| Replay of DATA (4.4, message manipulation) | A packet counter is accepted once, inside a 64-packet window, after AEAD verification | `ReplayWindow`, `open_data` | Defended | `test_replayed_packet_rejected`, `test_out_of_window_sequence_rejected` |
| Reflection of a response as a request (4.3.4) | The book's fix is to name both parties in the response. Here mac1 is keyed by the receiver's public key, so a message can be checked only by the party it was made for. Role separation is in the chaining key | `_mac1_key`, `make_initiation`, `make_response`, `_init_chain` | Defended | `test_reflected_handshake_messages_rejected`, `test_reflected_key_confirmation_tag_rejected` |
| Reflection of DATA to its sender | A sender's own packet, fed back to it, fails: the two directions use different keys | `_transport_keys`, `open_data` | Defended | `test_data_packet_is_not_accepted_by_the_sender_session` (new) |
| Parallel sessions (two runs mixed) | Each run has fresh ephemerals. The RESP is bound to the INIT's ephemeral through the chain, and echoes the INIT's sender index. A new INIT drops the old pending state | `consume_response`, `Node.initiate`, `Node._on_resp` | Defended | `test_superseded_response_is_ignored_and_fresh_one_completes` (new) |
| Interleaving (parts of two runs combined) | INIT's encrypted fields are chained into `h`, so a mixed INIT fails the AEAD. A RESP from one run cannot complete another | `make_initiation`, `consume_initiation`, `consume_response` | Defended | `test_bad_transcript_mac_rejected`, `test_superseded_response_is_ignored_and_fresh_one_completes` |
| Type confusion (a message read as another type) | Type byte, reserved bytes and exact length are checked before any field is used. Each type is tested with every other type | `_check_shape`, `Node.handle`, `_on_init`, `_on_resp`, `_on_cookie`, `_on_data` | Defended | `test_handshake_messages_retyped_as_another_type_are_dropped` (new), `test_reflected_handshake_messages_rejected` |
| Freshness of keys (4.7.3: a key may be old) | Each handshake makes new ephemeral keys. Sessions expire by time and by count | `make_initiation`, `_rekey_due`, `Node._expire`, `REJECT_AFTER_TIME` | Defended | `test_rekey_by_time`, `test_rekey_by_message_count` |
| Key-compromise impersonation, initiator's key leaks | The responder's proof needs the `es` term, which needs the responder's private key or the initiator's ephemeral. A RESP built from the initiator's key alone fails the tag. Derivation in THREAT_MODEL H-X10 | `make_response`, `consume_response` | Defended (by derivation and test) | `test_reflected_response_is_not_a_valid_initiator_proof` (new; control RESP accepted) |
| Key-compromise impersonation, responder's key leaks | **Mitigated by the ML-KEM step.** An attacker needs the responder's ML-KEM-768 secret as well as its X25519 key to open an INIT, so the X25519 key alone is not enough. A stolen ML-KEM key is the remaining exposure (static, rotate by hand) | `_init_chain`, `make_initiation`, `consume_initiation` | `test_leaked_server_x25519_key_alone_cannot_read_an_initiation` |
| Relay, "mafia-in-the-middle" (4.3.3) | A relay forwards INIT and RESP. It cannot read data or derive keys, but it can drop or delay. Detecting it needs distance or timing bounds, which are not used | n/a | Accept (THREAT_MODEL H-X12) | n/a |
| Chosen protocol attack (4.6): one key used in two applications | Nothing in code prevents reuse. `vpn_keygen.py` now warns on stderr and in its docstring | `vpn_keygen.py` | Partly | `test_keygen_warns_against_key_reuse` (new) |
| Revocation (4.7.3: Charlie holds Alice's key) | Removing a peer drops its keys, pending state and sessions. Without certificates there is no revocation list; removal is local | `Node.remove_peer` | Defended (locally) | `test_removed_peer_cannot_handshake_again`, `test_removed_peer_session_is_dropped` |
| Changing environment (4.5) | The clock is used only for timestamps, and only in strictly increasing order per peer. The TUN device and IPv6 are outside the core | `_tai64n`, `Peer.next_timestamp` | Partly (IPv6 outside the tunnel is open, THREAT_MODEL section 6) | `test_timestamps_strictly_increase_per_peer` |
| Endpoint moves on handshake, before data confirms it | Fixed in a later pass, with no protocol change. `_on_init` no longer sets the endpoint. The RESP still goes to the sender's address, and the endpoint moves on the first authenticated packet of the new session in `_on_data`. A replayed INIT therefore cannot move the endpoint, because the replayer lacks the session keys. Before the fix, a captured INIT sent first from a spoofed address moved the endpoint once. How the WireGuard reference handles this was not checked | `Node._on_init`, `Node._on_data` | Fixed (Low) | `test_replayed_init_after_restart_does_not_move_endpoint`, `test_legitimate_new_session_moves_endpoint_on_first_data` (test_hardening.py) |

Findings from this chapter:

- No coding error was found in the handshake or data path. Two protocol-level items stay open: the
  responder-key impersonation above, which is a property of the design, and the Low endpoint item
  at the end of the table (now fixed; see finding 3).
- The defence against reflection is the receiver-keyed mac1 and the type and length checks. The
  explicit sender-index check in `consume_response` is redundant with the AEAD. A mutation that
  removes it was not caught by any test, which is expected because the AEAD still rejects the
  message.

## 2. Chapter 5: cryptography (keys, nonces, MACs, key management)

| Claim | Code location | Status | Test |
|---|---|---|---|
| Nonce uniqueness: handshake AEAD uses a zero nonce, but each message has a fresh key from the chain | `_aead_seal`, `ZERO_NONCE`, `make_initiation` | Defended | `test_tampered_auth_message_rejected` |
| Data nonce is a counter, and sending stops before it wraps | `_data_nonce`, `seal_data`, `REKEY_AFTER_MESSAGES` | Defended | `test_sequence_limit_forces_rekey` |
| Key separation: one label per direction, cookie keys per salt | `_transport_keys`, `_cookie_key` | Defended | `test_child_keys_distinct_per_direction_and_purpose` |
| MAC: keyed BLAKE2s (no length extension), HMAC-BLAKE2s for the KDF | `_mac`, `_hmac_b2s`, `_kdf` | Defended | `test_blake2s_keyed_official_kat`, `test_hmac_blake2s_is_rfc2104_hmac`, `test_kdf_is_noise_hkdf_with_two_outputs` |
| Verify before use: AEAD tag checked before plaintext is used | `open_data`, `_aead_open` | Defended | `test_tampered_ciphertext_rejected` |
| Tag length 128 bits for mac1, mac2 and AEAD | `TAG_LEN` | Defended | Unit tests on the tag checks |
| Padding is inside the AEAD, so it is not an oracle | `seal_data`, `open_data` | Defended | `test_padding_is_stripped` |
| Low-order public keys refused | `_is_low_order`, `public_key_from_b64`, `Node.add_peer` | Defended | `test_low_order_points_refused_in_config` |
| Fixed suite, no downgrade (book: algorithm agility) | Constants, `CONSTRUCTION` | Accept (H-X5). No version field on the wire (see section 6) | n/a |
| Key management: keys in env vars or files, no PKI | `load_static_private`, `load_peer_publics` | Partly. Key-file mode is ignored on Windows (K-I3) | `test_static_keys_are_not_in_source` |

No new gap was found in chapter 5 that the earlier reviews miss. The checks above are claims with
their tests, not new findings.

## 3. Chapter 19: side channels

| Claim | Code location | Status | Test |
|---|---|---|---|
| Tag comparisons are constant time | `_check_mac1`, `_check_mac2` (`hmac.compare_digest`) | Defended | `test_mac1_rejects_wrong_tag`, `test_mac2_rejects_wrong_tag_and_wrong_address` |
| DH with a secret key (timing, power) | `X25519PrivateKey.exchange` in the `cryptography` library | Partly. Library behaviour not inspected here (SIDE_CHANNEL_REVIEW) | n/a |
| AES cache-timing (book 19.4.1) | AES is not used. The data path is ChaCha20-Poly1305 | N/A | n/a |
| Padding and error handling leak secrets (book 19.4.1, last paragraph) | Padding is checked only after AEAD. Handshake failures give one reason (`HS_FAIL`) and no reply. Bad mac1 is silent | `open_data`, `Node.handle`, `_on_init` | `test_mac1_checked_silently`, `test_unauthenticated_floods_keep_no_state` |
| Error reasons are visible to the operator | Data drops log a fixed reason per datagram (`auth failed`, `out of window`). They are local logs, not replies | `open_data`, `Node._on_data` | Not tested; the reasons are fixed strings |
| Branch on mac2 under load shows whether DH ran | Reveals only whether mac1 was valid, and anyone can compute mac1 from the public key. No secret is exposed | `Node._on_init` | n/a |
| Power, EM, acoustic and optical channels (19.2, 19.5) | Device-level. A software prototype on a general PC is not defended | n/a | n/a |
| Fault injection, glitching (19.4.3 heading) | Open. A glitch that skips a tag check would accept a forgery. Needs physical access and is out of scope | n/a | n/a |
| Rowhammer, CLKscrew, Spectre (19.4.4, 19.4.5) | Open. Hardware and OS level | n/a | n/a |
| Key material left in Python memory | Open (CRYPTO F6). No wiping is claimed | n/a | n/a |

## 4. Chapter 20: implementation pitfalls

| Claim | Code location | Status | Test |
|---|---|---|---|
| xor-to-null-key attack (20.5.1): a key combined with itself gives a known key | No key is XORed anywhere (grep). The all-zero PSK is refused, and an all-zero DH output is refused | N/A for XOR. Defended for zero keys | `test_all_zero_psk_is_rejected` (test_fixes.py), `test_dh_rejects_all_zero_output` |
| Keys with one purpose each | Static key is used only in DH. PSK enters the KDF and the mac1 key, each with a label | Defended | `test_child_keys_distinct_per_direction_and_purpose` |
| Differential protocol attacks (20.5.3): two parsers disagree | One parser. Size and shape checks run before any field is read | Defended | `test_oversized_datagrams_dropped_before_parsing`, `MutationFuzzTests` (new) |
| Backwards compatibility and downgrade (20.5.2) | No negotiation | Accept (H-X5) | n/a |
| Signal-style ratchet, enclaves, HSMs, blockchains (20.2 to 20.8) | Not applicable to this design. Per-session forward secrecy only (CRYPTO F5) | Accept | n/a |

## 5. Chapter 21: network attack and defence

| Claim | Code location | Status | Test |
|---|---|---|---|
| A VPN provides encryption and authentication at the IP layer (21.5.2.4) | Encrypted, authenticated tunnel with an ESP-style trailer (`seal_data`, `open_data`). Not IPsec and not interoperable (NETWORK_SECURITY_REVIEW) | Defended for the tunnel's own traffic | `test_round_trip_both_directions`, `test_tampered_header_rejected` |
| IKE with weak defaults (21.5.2.4) | No IKE. X25519 handshake with pinned keys | Defended by design | n/a |
| SYN-cookie style DoS protection (21.2, "SYNcookie") | Cookie reply that holds no state, bound to the source IP and to the INIT's mac1 | Defended for CPU per source. Open for bandwidth (below) | `test_cookie_reply_roundtrip`, `test_cookie_reply_bound_to_initiation`, `test_mac2_checked_under_load` |
| UDP reflection and amplification (21.4.1.4, 21.2 DNS) | Replies are smaller than the request, and need a valid mac1. Data gets no reply. Asserted in the new tests | `Node._on_init`, `Node.handle` | `test_responses_are_smaller_than_the_initiation` (new), `test_authenticated_data_gets_no_reply` (new) |
| Anti-spoofing at the perimeter (21.4.1.4, ingress filtering) | README rule 2 drops inside-prefix sources on the public interface. No egress rule. Not applied or run | `README.md` firewall section | n/a |
| Volumetric DDoS: floods that fill the link or the CPU from many sources | **Open.** No per-source rate limit or bandwidth cap. Filtering must be upstream | THREAT_MODEL U-D1, U-D5, P-D3 | None |
| The VPN does not stop traffic analysis, endpoint compromise, or IPv6 outside it | Documented | THREAT_MODEL section 7 | n/a |

## 6. Chapters 27 and 28: process, evidence and sustainability

Book steps (27.5.3) against this repo:

| SDL step | Evidence in repo | Status |
|---|---|---|
| Requirements, bug bar | THREAT_MODEL states the goals. No bug bar or review cadence | Partly |
| Design, threat modelling | THREAT_MODEL.md, with STRIDE tables and a status per threat | Defended |
| Implementation, approved tools and static analysis | None run. No type or security linter in the repo | Open |
| Verification, dynamic analysis and fuzzing | 140 unit tests. A seeded mutation fuzz test (`MutationFuzzTests`, new). No coverage-guided fuzzer | Partly |
| Release, incident response plan and final review | Review documents only. No incident response plan | Open |
| Regression testing (27.5.2) | Full suite run after each change, with the count reported | Defended |
| Vulnerability intake (27.5.7) | No disclosure policy or contact | Open |

Hostile review and evidence (28.2 to 28.3):

| Claim | Evidence | Status |
|---|---|---|
| Independent review of the design (28.3.2) | All reviews are by the author or by agents working on this repo. Not hostile in the book's sense | Open |
| Evaluation under Common Criteria or FIPS (28.2) | None. None is claimed | Open |
| Mutation evidence | Four deliberate mutations were tried in scratch copies. Disabling mac1 was caught by `MutationFuzzTests`. Making both directions share one key was caught by `test_data_packet_is_not_accepted_by_the_sender_session`. Removing the sender-index check was not caught, because the AEAD rejects the same message. Dropping the responder key from the chain on both sides was not caught either, because the change is self-consistent (a one-sided change would fail the handshake, and no test pins the construction). Both are recorded as gaps in test strength, not as protocol flaws | Partly |

Sustainability (28.5): there is no version field in the wire format, and no path to a new suite,
key rotation beyond a manual change, or a published update. KEY_LIFECYCLE.md records the backup key
and pin update path as open. A future suite change needs a new format and a migration plan.

## 7. What would be needed to call it assured

1. An independent review of the handshake and data path, with a written scope and an attacker
   mindset. Its result must be recorded, including the responder-key limit above.
2. Known-answer tests against a reference: the official Noise vectors (not obtained, per
   CRYPTO_REVIEW F2) and the WireGuard reference, if interop is ever claimed.
3. A symbolic model of the handshake, checked with a tool, covering key-compromise impersonation and
   identity hiding.
4. Coverage-guided fuzzing of `Node.handle`, `consume_*` and `open_data`, run for hours, plus a real
   Linux run as root with the TUN backend.
5. Static analysis in the test run, with the result kept.
6. A written key-rotation, revocation and version plan, with a version field to add before any wire
   change.
7. A vulnerability intake, and a release gate that includes an incident response step.

## 8. Changes made in this review

| File | Change |
|---|---|
| `test_vpn.py` | New classes `ProtocolAttackTests` (10 tests) and `MutationFuzzTests` (2 tests) and a helper `forge_init_as`. Each test is named in the tables above with "(new)" |
| `vpn_keygen.py` | Docstring and a stderr line: use the key pair for this tunnel only (chosen protocol attack) |
| `THREAT_MODEL.md` | Rows U-D4, U-D5, H-X8 to H-X12, K-X2. Section 7 (what the tunnel does not stop). Fuzzing status corrected |
| `README.md` | Two Design bullets: limits of the DoS defences, and key compromise. Fuzzing status corrected |
| `SECURITY_ENGINEERING_REVIEW.md` | New. This file |

No production code path changed. No wire format changed. No dependency was added.

## 9. Open items, ranked

1. **Medium, open (design).** A leaked responder key lets an attacker pose as any client, unless a
   PSK is set. Fixing this needs a wire change, so it stays documented. A PSK is the mitigation, and
   it is a single shared secret for all peers (K-X1).
2. **Medium, open.** No defence against floods that fill the link or the CPU from many sources (U-D5).
3. **Low, fixed.** The endpoint no longer moves on an INIT. It moves on the first authenticated packet of the new session (section 1, and `test_hardening.py`).
   Read from the code, not run.
4. **Low, open.** No wire version field, so there is no migration path (section 6).
5. **Low, open.** No static analysis, no coverage-guided fuzzing, no independent review.
