# Threat model: ioessa VPN tunnel prototype (WireGuard-style design)

Method: Shostack, *Threat Modeling: Designing for Security* (ch.1 four questions, ch.3 STRIDE,
ch.4 attack trees, ch.7 managing threats, ch.8 defensive tactics, ch.16 cryptosystems), with the
crypto checks from Aumasson, *Serious Cryptography* (ch.2, 3, 5, 7, 8, 11, 12). The protocol is
taken from Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel" (NDSS 2017). Section
references below ("V-D2" and so on) point at that paper.

Scope: the `vpn_*` core modules listed in `README.md` (split out of `vpn_core.py` on 2026-10-17), `vpn_server.py`, `vpn_client.py`, `vpn_keygen.py` in this folder, loopback
UDP only. This is a learning prototype. It is not audited, it is not wire-compatible with the
`wg` tool, and it must not protect real traffic.

This file replaces the earlier ESP/IKE-style threat model. The earlier PSK-only IKE handshake and
its SPI-based SAs are gone. The transport keeps the ESP-style trailer and replay window.

---

## 1. What are we working on? (data-flow diagram)

```
  Client process (P1)                                         Server process (P2)
  vpn_client.py + vpn_node Node                               vpn_server.py + vpn_node Node
  static key C, peer pub S, SPD, sessions                     static key S, peer pub C, SPD, sessions
        |                                                              ^
        | (F1) inner IPv4, plaintext  [TUN stand-in: QueueTun, CLI]     | (F1') inner IPv4
        v                                                              |
  +-----------------+  (F2) INIT / RESP / COOKIE (handshake)  +-----------------+
  |  P1 client      |=========== UDP 127.0.0.1 (untrusted) ==>|  P2 server      |
  |  ESP encap/decap|<========== (F3) DATA: hdr | AEAD(...)  ==|  ESP encap/decap|
  +-----------------+  (F3 also carries keepalives, empty)    +-----------------+
        ^                                                              ^
        | (D1) static private key: env IOESSA_VPN_PRIVATE_KEY or file  |
        | (D2) peer public key: env IOESSA_VPN_PEER_PUBLIC_KEY or file |
        | (D3) optional PSK: env IOESSA_VPN_PSK, only with --use-psk   |
        +--------------------------------------------------------------+
```

Elements: P1 client, P2 server, F1/F1' inner plaintext (TUN side), F2 handshake, F3 data
(keepalives are empty data), D1 to D3 key material from the environment or files.

Trust boundaries: (a) process to network (every UDP datagram is attacker-controlled); (b)
environment and files to process (key material); (c) TUN or OS to tunnel (inner plaintext is
trusted only after AEAD verification, and only after the source check).

## 2. What can go wrong? (STRIDE per element and flow)

Status key: **Implemented** = in code and covered by a test or run. **Partial** = mitigated in
part, gap stated. **Not done** = absent. **Accept** = risk accepted for this prototype.
"Test" names are in `test_vpn.py`.

### Processes (P1, P2)

| ID | STRIDE | Threat | Mitigation | Status | Where / test |
|---|---|---|---|---|---|
| P-S1 | Spoofing | Fake server answers the client | Static-key handshake: the initiator checks the responder's proof (empty AEAD under the chained key, which needs the responder's static key) | Implemented | `consume_response`; `test_tampered_auth_message_rejected` |
| P-S2 | Spoofing | Fake client connects | Responder decrypts the initiator's static key and refuses unknown keys | Implemented | `consume_initiation`, `Node._on_init`; `test_wrong_psk_fails_authentication` |
| P-T1 | Tampering | Local config changed by another process | None (in-memory SPD and keys) | Accept | n/a |
| P-R1 | Repudiation | No record of who sent what | Logs show addresses and indices only | Not done | `vpn_server.py` `serve` |
| P-I1 | Info disclosure | Key or PSK in logs, exceptions or repr | `Session`, `InitState` and `InitInfo` hide keys in repr; key loaders never echo the value; tests check error messages | Implemented | `vpn_transport.py` and `vpn_handshake.py` dataclasses, `load_static_private`, `private_key_from_b64`; `KeyHandlingTests` |
| P-I2 | Info disclosure | Plaintext printed | `--show-payload` (demo flag, off by default) | Partial | `vpn_server.py`, `vpn_client.py` |
| P-I3 | Info disclosure | Server replies reveal which check failed | Silence for bad mac1 and for unknown keys or bad timestamps. Only a cookie reply is sent (it needs a valid mac1). Handshake failures use one generic reason | Implemented | `Node._on_init`; `test_mac1_checked_silently`, `test_unauthenticated_floods_keep_no_state` |
| P-D1 | DoS | Malformed datagram crashes the server | Size and type checks run before any parsing. `Node.handle` catches `HandshakeError` and `ESPError` and logs them. Any other exception is contained per datagram by `vpn_server._safe_handle` (and per timer run by `_safe_poll`): the server logs the exception type only and keeps serving | Implemented | `Node.handle`, `vpn_server._safe_handle`; `test_server_survives_malformed_init_then_auth`, `test_oversized_datagrams_dropped_before_parsing`, `test_serve_resilience` |
| P-D2 | DoS | Authenticated peer sends a non-IPv4 or empty inner datagram | Empty = keepalive (valid). Non-IPv4 is caught per packet by `describe` | Implemented | `serve`; `test_authenticated_empty_inner_does_not_crash_server` |
| P-D3 | DoS | Flood of INITs exhausts memory or CPU | Responder keeps no state for unauthenticated input (V-A). Under load, INITs without a valid mac2 get a cookie reply and no DH (V-C). A per-source token bucket (SRC_INIT_RATE 2/s, burst 20, table bounded at 4096) refuses INITs from one address before any DH. State is bounded by peers and by the source table. Spoofed sources evade the bucket, so the cookie check remains the main defence | Partial | `Node._source_budget`, `Node._on_init`; `test_flood_from_one_source_is_refused_after_the_burst`, `test_bucket_table_is_bounded`, `test_mac2_checked_under_load` |
| P-D4 | DoS | Flood from other addresses keeps the client waiting | Overall receive deadline, filtering of non-server datagrams | Implemented | `vpn_client.py` `_recv_from`; `test_receive_has_overall_deadline` |
| P-E1 | Elevation | Process runs with extra privileges | The default queue mode and the tests need no admin rights. `--tun linux` needs root or CAP_NET_ADMIN, and the process keeps those rights after the device is set up (no privilege drop, open; section 6). Server binds 127.0.0.1 by default | Partial (privilege drop open) | `vpn_server.py` `--bind`; `tun_linux.py` |

### UDP path (F2 and F3, untrusted network)

| ID | STRIDE | Threat | Mitigation | Status | Where / test |
|---|---|---|---|---|---|
| U-S1 | Spoofing | Source address forged | Source is not trusted for identity. Data is accepted only after AEAD verification. Roaming moves the endpoint only after that check | Implemented | `Node._on_data`; `test_forged_or_replayed_packet_does_not_roam` |
| U-T1 | Tampering | Bits flipped in header or ciphertext | AEAD over ciphertext, with the 16-byte header as associated data | Implemented | `seal_data`, `open_data`; `test_tampered_*` |
| U-T2 | Tampering | Handshake bytes altered | Each message has mac1 (keyed by the receiver's key). The encrypted parts are chained into the hash, so any change fails the AEAD | Implemented | `make_initiation`, `consume_initiation`, `consume_response`; `test_bad_transcript_mac_rejected`, `test_mac1_checked_silently` |
| U-R1 | Repudiation | Peer denies sending | Static keys authenticate each peer, but nothing is logged or signed for third parties | Partial | n/a |
| U-I1 | Info disclosure | Traffic analysis: sizes, timing, indices, counters visible | Indices and counters are in clear by design (V-D6). Only 4-byte padding, no cover traffic | Not done | `seal_data` |
| U-I2 | Info disclosure | Initiator's identity visible to the network | The initiator's static key is encrypted in INIT (identity hiding, V-D2). Responder's key is not secret (paper V-C) | Implemented | `make_initiation`; `test_identity_hidden_on_wire` |
| U-D1 | DoS | Garbage flood costs CPU | Size bound before parsing, mac1 before DH, per-source INIT budget, cookie under load | Partial (per-source budget; spoofed sources not bounded) | `Node.handle`, `Node._on_init`, `Node._source_budget` |
| U-D2 | DoS | Oversized datagram parsed | Datagrams over `MAX_ESP` are dropped before parsing | Implemented | `Node.handle`; `test_oversized_datagrams_dropped_before_parsing` |
| U-D3 | DoS | Replayed INIT forces the responder to regenerate state | Per-peer TAI64N timestamp, encrypted and authenticated. Not greater than the last one: silent drop (V-A). This holds in-process. After a restart it holds only with `--state-file` (section 7, row "Captured INIT replayed after a server restart"); without the file, a replayed INIT is accepted again and the responder creates a pending session for it (the endpoint does not move) | Partial (in-process; across restart only with `--state-file`) | `Node._on_init`, `Peer.last_init_ts`; `test_replayed_initiation_rejected`, `test_old_timestamp_rejected`; `test_replayed_initiation_rejected_after_restart` (test_state.py) |
| U-D4 | DoS (reflection, amplification) | A spoofed source makes the tunnel send more bytes at the victim than it receives | Replies are smaller than the request: cookie reply 72 bytes and RESP 1180 bytes, against INIT 1236. A cookie reply needs a valid mac1. Authenticated data gets no reply. Spoofed INITs are answered only with a cookie, under load | Implemented | `Node._on_init`, `Node.handle`; `test_responses_are_smaller_than_the_initiation`, `test_authenticated_data_gets_no_reply` |
| U-D5 | DoS (volume) | A flood that fills the link or the CPU from many sources | Not stopped. Cookies cap the CPU cost per source, and a per-source INIT budget applies to real addresses. There is no bandwidth cap, and spoofed sources are not bounded. Filtering must happen upstream (Ch. 21) | Partial | `Node._source_budget`; section 7 |

### Handshake (F2, Noise IK over X25519 plus ML-KEM-768, ChaCha20-Poly1305, BLAKE2s; V-D1 to V-D4, V-D7)

| ID | STRIDE | Threat | Mitigation | Status | Where / test |
|---|---|---|---|---|---|
| H-S1 | Spoofing | Attacker without the responder's key completes a handshake | Initiator's DH uses the responder's static key, so only the holder can derive the chaining key that opens the AEAD | Implemented | `consume_initiation`; `test_auth_with_correct_transcript_is_accepted` |
| H-S2 | Spoofing | Offline guessing of a weak PSK | PSK is an optional extra secret (V-B). Without it there is no password to guess. With it, the PSK must be random, and nothing checks entropy | Partial | `load_psk` |
| H-T1 | Tampering | Public key or nonce altered in transit | Hash chain over every field (V-D2, V-D3) | Implemented | `test_bad_transcript_mac_rejected` |
| H-I1 | Info disclosure | Static key or timestamp sent in clear | Static key and timestamp are AEAD-encrypted in INIT. Only ephemerals are clear | Implemented | `make_initiation` |
| H-D1 | DoS | Half-open handshakes exhaust server memory | No state before authentication. Pending state is one per configured peer | Implemented (bounded by peer count) | `Node` |
| H-D2 | DoS | Forged message kills a live session | Sessions change only on a verified RESP or INIT with a newer timestamp | Implemented | `test_replayed_initiation_rejected` |
| H-X1 | Reflection | Message of one type replayed as another | Type and reserved bytes checked; receiver index in RESP and COOKIE | Implemented | `_check_shape`; `test_reflected_*` |
| H-X2 | Unknown key share | Peer keyed to a different identity | Both static keys are in the chained hash (`_init_chain` mixes the responder's key; the initiator's key is encrypted under it) | Implemented | `test_reflected_handshake_messages_rejected` |
| H-X3 | Low-order peer point | All-zero shared secret | Explicit all-zero check plus the library's error, both mapped to `HandshakeError` | Implemented | `_dh`; `test_all_zero_shared_secret_rejected`, `test_low_order_peer_public_key_rejected_by_responder` |
| H-X4 | Key confusion | One key used for two purposes or directions | Kdf outputs chained per step (V-D1). Transport keys have their own labels per direction | Implemented | `_transport_keys`; `test_child_keys_distinct_per_direction_and_purpose` |
| H-X5 | Downgrade / version | Negotiation of weaker suites | No negotiation: one fixed suite. The paper justifies this by the cost of updating endpoints when a primitive breaks (L121-125), not by a downgrade argument | Accept (by design) | n/a |
| H-X6 | Timing | Timing leak in MAC comparison | `hmac.compare_digest` for mac1, mac2, and the empty tag check | Implemented | `_check_mac1`, `_check_mac2` |
| H-X7 | Forward secrecy | Long-term key leak exposes old traffic | Fresh ephemeral X25519 per handshake, and sessions rekeyed every 120 s when used (V-D2, VI-B) | Implemented | `make_initiation`, `Node.poll` |
| H-Q1 | Confidentiality (quantum) | Recorded handshake and traffic decrypted later by a large quantum computer that breaks X25519 | Transport keys depend on static ML-KEM-768 secrets (`make_initiation`, `make_response`), which are never sent in the clear. A quantum break of X25519 alone does not reveal them. This does not claim unbreakable: it assumes ML-KEM-768 and the implementation hold | Implemented, not audited | `make_initiation`, `consume_initiation`, `make_response`, `consume_response`; `test_handshake_produces_matching_sas`, `test_tampered_ml_kem_ciphertext_is_rejected`, `test_responder_refuses_an_invalid_ml_kem_key` |
| H-Q2 | Authentication (quantum) | A quantum computer that breaks X25519 forges a peer | Impersonation needs the peer's ML-KEM-768 private key as well as its X25519 key. Forging needs both broken. Residual: a stolen ML-KEM key (static, not rotated) exposes that node's sessions, and a stolen X25519 key still cannot forge it | Implemented (both keys required), not audited | `test_leaked_server_x25519_key_alone_cannot_read_an_initiation`, `test_leaked_client_x25519_key_alone_gives_no_session` |
| H-Q3 | Downgrade (quantum) | An attacker strips the ML-KEM step | No negotiation. INIT and RESP always carry the ML-KEM ciphertext, and it is mixed into the keys. A peer with no ML-KEM key is never sent an INIT (fail closed). A message of the wrong length is refused by `_check_shape` | Implemented | `_check_shape`; `test_tampered_ml_kem_ciphertext_is_rejected`, `test_peer_without_an_ml_kem_key_cannot_handshake` |
| H-X8 | Parallel sessions, interleaving | A RESP from one handshake completes another, or an old RESP is replayed | RESP is bound to the INIT's ephemeral (chain), to the INIT's sender index (echoed), and to the pending state by index. A superseded INIT's state is dropped. A RESP after tunnel-up finds no pending state | Implemented | `consume_response`, `Node._on_resp`; `test_superseded_response_is_ignored_and_fresh_one_completes`, `test_replayed_response_after_tunnel_up_changes_nothing` |
| H-X9 | Reflection of data | A packet sent by one side is returned to it | Direction keys differ (`_transport_keys`), so the sender's receive key rejects its own packet | Implemented | `open_data`; `test_data_packet_is_not_accepted_by_the_sender_session` |
| H-X10 | Key-compromise impersonation, initiator key leaks | With the initiator's static key, an attacker poses as the responder to that initiator | The responder's proof needs the `es` term, which needs the responder's key or the initiator's ephemeral. A RESP built from the initiator's key alone fails the tag | Implemented (by derivation and test) | `make_response`, `consume_response`; `test_reflected_response_is_not_a_valid_initiator_proof` |
| H-X11 | Key-compromise impersonation, responder key leaks | With the responder's X25519 key alone, an attacker cannot open an INIT or answer one: the chaining key also needs the responder's ML-KEM-768 secret. Impersonation needs both keys | Mitigated by the ML-KEM step (both keys needed). Stolen ML-KEM key still exposes that node's sessions (static, not rotated) | Implemented; `test_leaked_server_x25519_key_alone_cannot_read_an_initiation` |
| H-X12 | Relay (mafia-in-the-middle) | A relay forwards INIT and RESP between a client and a real server | Not defended. The relay cannot read data or forge a key, but it sits in the path and can drop or delay traffic. Detecting relays needs distance or timing bounds, which are not used | Accept (documented) | n/a |

### Cookies (DoS, V-C, V-D4, V-D7)

| ID | STRIDE | Threat | Mitigation | Status | Where / test |
|---|---|---|---|---|---|
| C-D1 | DoS | Spoofed INIT from a victim address gets the victim's cookie | Cookie is a MAC over the source IP with a rotating secret. The cookie reply is encrypted with a key from the responder's public key and a random salt, and bound to the INIT's mac1 | Implemented | `make_cookie_reply`, `consume_cookie`; `test_cookie_reply_roundtrip` |
| C-D2 | DoS | Cookie reply forged to stop the initiator | Cookie reply is AEAD-checked with the INIT's mac1 as associated data. Forged or misbound replies are ignored | Implemented | `test_cookie_reply_bound_to_initiation` |
| C-D3 | DoS | Cookie for one source reused from another | mac2 keyed by a cookie bound to the source IP | Implemented (IP only) | `test_cookie_is_bound_to_source_address` |
| C-D4 | DoS | Cookie secret never rotates | Rotates every 120 s; the previous secret still validates | Implemented | `test_cookie_secret_rotates` |
| C-X1 | Spoofing | Cookie binds to IP only, not IP and port | Deliberate: ports change under NAT and roaming (II-A). Two peers behind one NAT IP share the cookie space | Accept (documented deviation) | n/a |

### Data path and roaming (F3)

| ID | STRIDE | Threat | Mitigation | Status | Where / test |
|---|---|---|---|---|---|
| D-T1 | Tampering / nonce reuse | Counter repeats under one key | Keys are fresh per session. Counter is in the nonce. Sending stops at the limit (2^32 - 1024) and raises `RekeyRequired` | Implemented | `seal_data`; `test_sequence_limit_forces_rekey` |
| D-R1 | Replay | Old data packet replayed | 64-packet sliding window, updated only after AEAD verification | Implemented | `ReplayWindow`; `test_replayed_packet_rejected`, `test_out_of_window_sequence_rejected` |
| D-S1 | Spoofing | Authenticated peer sends inner packets with a forged source | Reverse-path check: decrypted inner source must fall in the peer's `allowed_ips` (II, III step 4). Default is any source, so configure it per peer | Implemented (default permissive) | `Node._source_allowed`, `Peer.allowed_ips` |
| D-R2 | Roaming hijack | Attacker moves the endpoint by sending bogus packets | Endpoint updates only after AEAD verification, the replay check and the inbound source check. An INIT does not move it: the endpoint follows the first authenticated packet on the new session | Implemented | `test_forged_or_replayed_packet_does_not_roam`; `test_replayed_init_after_restart_does_not_move_endpoint`; `test_refused_packet_does_not_promote_or_roam` (test_hardening.py) |
| D-K1 | Keepalive abuse | Keepalive used to hold the tunnel open forever | Keepalive is sent only after authenticated data, and only once per idle period (VI-E) | Implemented | `Node.poll`; `KeepaliveTests` |
| D-T2 | Tampering | Inner packet altered | AEAD over the whole inner datagram and trailer | Implemented | `open_data`; `test_tampered_ciphertext_rejected` |
| D-I1 | Info disclosure | Inner packet visible | ESP encryption; inner header is inside the ciphertext | Implemented | `seal_data` |
| D-I2 | Info disclosure | Traffic that should be protected goes out unprotected | Client default is BYPASS outside `--protect`. Server echo uses PROTECT for 0.0.0.0/0. An empty SPD means DISCARD | Partial (design choice) | `vpn_client.py` `main`, `vpn_server.py` `main`, `Peer.route` |
| D-E1 | Elevation | Decrypted packets injected into the OS stack | `LinuxTun` writes decrypted packets to the host stack, after the replay check, the AEAD check and the inbound source check, and only for IPv4 (`serve_tun`, `run_tun`). The Linux device has not been run on a kernel (section 6). No Windows TUN (`QueueTun` is in memory) | Partial (Linux path unit-tested, not run on a kernel) | `serve_tun`, `run_tun`, `LinuxTun`; `test_authenticated_non_ipv4_inner_is_not_written_to_device` |

### Timers and rekey (VI)

| ID | STRIDE | Threat | Mitigation | Status | Where / test |
|---|---|---|---|---|---|
| R-T1 | Tampering | Sequence wraps and repeats a nonce | Refuses to send at the limit | Implemented | `seal_data` |
| R-S1 | Spoofing | Old session accepted after rekey | Old session kept only as `previous` for in-flight packets. Discarded at the next rekey, and after 3 x 180 s (VI-C). The age limit is enforced by `poll()`, which `serve()` and `serve_tun()` now run once per tick (1 s) even under steady traffic, so a session is dropped within one tick of its limit. The receive path does not check session age itself | Implemented (expiry within one tick; not per packet) | `Node._set_current`, `Node._expire`; `test_rekey_by_time`; `TimersUnderLoadTests` (test_hardening.py) |
| R-R1 | Replay | Old packets replayed into the new session | Different keys and indices per session; per-session replay window | Implemented | `Session.replay` |
| R-D1 | DoS | Any peer forces repeated rekeys | Initiation is rate-limited to one per 5 s (VI-A). Retransmission backs off (5 s doubling to a 20 s cap, +/-20 % jitter) and gives up after 90 s | Implemented | `Node._retry_interval`, `Node.poll`; `test_gaps_double_then_cap_and_attempt_is_bounded`, `test_jitter_is_applied_to_every_gap` |
| R-D2 | DoS | Stale data from an old session breaks a new handshake | Handshake responses are matched by receiver index and checked | Implemented | `Node._on_resp` |
| R-D3 | DoS | Responder cannot send until it gets data | Responder promotes its new session on its first authenticated data (V-C). The initiator sends an empty confirmation keepalive right after the response, so this does not stall | Implemented | `Node._on_data`, `Node._on_resp`; `test_responder_can_initiate_rekey` |
| R-D4 | Availability | Server cannot rekey on its own | Either side can initiate: `Node.poll` runs the same rule on both | Implemented | `test_responder_can_initiate_rekey` |
| R-D5 | Availability | Both peers rekey at once and each side drops the other's session | A due rekey waits a random 0 to 5 s. If the two INITs still cross, the lower ephemeral key wins, the winner ignores the other INIT, and the loser answers (RFC 7296 2.8.1). Both sides see both keys, so no extra round trip | Implemented | `Node._on_init`, `Node.poll`; `test_both_sides_can_send_and_receive_after_the_collision`, `test_exactly_one_attempt_is_answered` |

### Key material (D1 to D3)

| ID | STRIDE | Threat | Mitigation | Status | Where / test |
|---|---|---|---|---|---|
| K-I1 | Info disclosure | Keys in source | Keys come from env vars or files only. Test scans the shipped modules for base64 literals | Implemented | `load_static_private`, `load_peer_publics`; `test_static_keys_are_not_in_source` |
| K-I2 | Info disclosure | Other same-user processes read env vars | None (OS-level exposure) | Accept | n/a |
| K-I3 | Info disclosure | Key file readable by others | `vpn_keygen.py --out` creates the file exclusively with mode 0600 where the OS honours it. On load, POSIX refuses group or other access. On Windows, `_check_windows_acl` refuses any principal other than the user, SYSTEM or Administrators (names matched in English) | Implemented (POSIX, English Windows). Localized Windows may need the extra entries removed | `vpn_keygen.py`; `_check_key_file_mode`, `_check_windows_acl`; `KeyFileModeTests` |
| K-T1 | Tampering | Weak PSK | 32-byte minimum, hex only. No entropy check | Partial | `load_psk` |
| K-T2 | Tampering | Mis-typed peer key accepted | Keys must decode to 32 bytes that are not a small-order X25519 point (all-zero and the other small-order encodings are refused, `_is_low_order`). A wrong key simply fails the handshake | Implemented | `public_key_from_b64`, `Node.add_peer`; `test_low_order_points_refused_in_config` |
| K-D1 | DoS | Missing key stops the program | Clear error, value not printed | Implemented | `load_static_private` |
| K-X1 | Scope | One PSK shared by every peer | Known limit: a single `--use-psk` secret for all peers. Per-peer PSKs are not implemented | Accept (documented) | `Node.psk` |
| K-X2 | Chosen protocol attack | The same key pair is used in another protocol or app, which lets an attacker use one to break the other (Ch. 4) | Not enforceable in code. `vpn_keygen.py` prints a warning and its docstring says one use only | Partly | `vpn_keygen.py`; `test_keygen_warns_against_key_reuse` |

## 3. What should we do about it? (decisions)

- **Mitigate**: AEAD, the hash chain, mac1 and mac2, cookies under load, size bounds, the replay
  window, timestamps, generic errors.
- **Eliminate**: no key in code; no error replies on the wire; no `random` module.
- **Accept**: local-process attacks (P-T1, K-I2), the fixed suite (H-X5), and per-IP (not per
  IP and port) cookies (C-X1).
- **Stricter than the paper, kept on purpose**: the 16-byte header is AEAD associated data
  (the paper leaves it unauthenticated); the message limit is 2^32 - 1024, not the paper's 2^60;
  the counter starts at 1 (the replay window rejects 0); padding is 4-byte ESP-style, not 16-byte;
  a packet with a source outside `allowed_ips` is dropped after the replay check.
- **Not done, with reason**: per-source rate limiting (U-D1, P-D3 across sources), per-peer PSKs
  (K-X1), ESN, IPv6, real TUN, and zeroing of secrets. Python cannot give a reliable zeroing
  guarantee, so the code drops references and makes no stronger claim.

## 4. Did we do a decent job? (crypto checklist)

| Check | Result | Where / note |
|---|---|---|
| Nonce uniqueness per key | Pass. Each session has fresh keys from a new X25519 exchange, and the counter is unique per session. The limit is enforced before wrap | `_data_nonce`, `seal_data`, `REKEY_AFTER_MESSAGES` |
| Tag verified before plaintext used | Pass: AEAD decrypt returns only after the tag verifies | `open_data`, `_aead_open` |
| AD binds header | Pass: AD is the 16-byte data header | `seal_data`; `test_tampered_header_rejected` |
| All-zero shared secret | Pass: explicit check plus library error | `_dh`; `test_all_zero_shared_secret_rejected` |
| Transcript binding | Pass: every encrypted field is hashed into the chain, and mac1 covers the whole message | `make_initiation`, `consume_initiation`; `test_bad_transcript_mac_rejected` |
| Reflection | Pass: type byte and reserved bytes checked, role separated by chain, receiver index | `_check_shape`; `test_reflected_*` |
| Key separation | Pass: transport keys have per-direction labels; cookie keys are per salt | `_transport_keys`, `_cookie_key`; `test_child_keys_*` |
| Constant-time compare | Pass: `hmac.compare_digest` for mac1, mac2 | `_check_mac1`, `_check_mac2` |
| Randomness | Pass: `os.urandom` for ephemerals, secrets and cookie salt; `secrets` for indices. No `random` module | the `vpn_*` core modules |
| Timestamps | Pass: TAI64N, big-endian; per-peer strictly increasing even if the clock steps back | `Peer.next_timestamp`; `test_timestamps_strictly_increase_per_peer` |
| Replay window edges | Pass: distance 63 accepted, 64 rejected; jump clears old bits | `HardenedReplayTests` |
| Error handling | Pass: one generic handshake reason; no reply to unauthenticated input | `HS_FAIL`, `Node.handle` |
| Key material in logs | Pass: no key printed; reprs omit keys | dataclass `repr=False` |

## 5. Not verified (keep these in view)

- **Interoperability with the real WireGuard tool or kernel module**: not tested and not claimed.
  The labels "mac1----" and "cookie--" come from the WireGuard reference protocol, because the
  extracted paper text does not show them. The Kdf is written from the paper's definition over
  HMAC-BLAKE2s, since `cryptography` has no BLAKE2s.
- **Real TUN device (Linux `LinuxTun`)**: written, unit-tested without root, and not run on a
  Linux kernel. WSL is not installed on the test machine. See section 6.
- **Wintun (Windows)**: not implemented, not run.
- **Real networks, packet loss, NAT, IPv6, path MTU**: only loopback 127.0.0.1 was run. Roaming
  was run only as a port change on loopback.
- **Formal proof** of the handshake or of the data path. Arguments are informal and based on the
  paper and Aumasson.
- **Fuzzing**: only a seeded mutation test (`MutationFuzzTests` in `test_vpn.py`, 300 rounds each
  for handshake and data). No coverage-guided fuzzer has been run, and the TUN backend is not fuzzed.
- **Side channels in Python** (interpreter timing, memory copies, GC). Only the compares are constant-time.
- **Per-source rate limiting and CPU bounds under a distributed flood**: not implemented.
- **Cookie secret rotation under long idle periods**: the secret is rotated when the node next
  runs a cookie check, so a node idle for several minutes keeps one older secret.
- **Real-clock behaviour of rekey and keepalive timers**: tested with a fake clock only. The
  loopback run did not exercise the time-based rekey or the keepalive.
- **PSK entropy and rotation**: not checked.

## 6. Linux TUN backend (`tun_linux.py`, `--tun linux`)

The backend moves inner packets between the kernel and the tunnel, so it widens the trust
boundary. It runs as root or with CAP_NET_ADMIN.

| Threat | Mitigation | Where | Status |
|---|---|---|---|
| Command injection through the interface name, address, MTU or route | `ip` is run with an argument list and `shell=False`. Every value is validated first (name, CIDR, MTU range, route). Nothing runs if validation fails | `build_ip_commands`, `_run_ip`, `test_tun.py` ValidationTests and CommandTests | Pass (unit tests) |
| Traffic hijack: the host routes everything into the tunnel, cutting itself off | The default route (0.0.0.0/0) is refused | `validate_route` | Pass (unit test) |
| Spoofed inner source after decryption (a peer claiming another address) | Cryptokey routing: in TUN mode each peer's `allowed_ips` is set to the tunnel routes. The server refuses to start with two or more peers, because their routes would overlap (`check_allowed_ips_disjoint`) | `vpn_server.main`, `vpn_client.main`; `test_hardening.py` SourceClaimTests | Set in code; not run on a kernel |
| Packets that are not IPv4 in the device stream (for example IPv6 frames the kernel emits) | Dropped before encryption, because the ESP trailer carries next header 4 only. The receive side also checks for IPv4 before writing to the device, so an authenticated peer cannot inject a non-IPv4 frame (added in the Ch. 9 review) | `is_ipv4`, `serve_tun`, `run_tun`; `test_authenticated_non_ipv4_inner_is_not_written_to_device` | Pass (unit test) |
| Oversized inner packets causing fragmentation or silent loss | TUN MTU 1400 = 1500 - 65 bytes overhead, capped at `MAX_INNER`. Overhead checked against sealed packets | `max_tun_mtu`, `test_overhead_matches_packets_sealed_by_the_core` | Pass (unit test) |
| Device name collision or leftover state | Non-persistent device, so it and its routes vanish when the fd closes. An in-use name fails with EBUSY, with a clear error | `LinuxTun.__init__` | Not run on a kernel |
| Privilege: root needed to attach the device | The core does no privileged work. The backend asks the kernel for one TUN device and does not touch others | `LinuxTun` | Design only |
| Information leak: IPv6 that is not tunnelled | Not mitigated. The host may send IPv6 outside the tunnel. Disable IPv6 on the device or on the host if that matters | README | Open |
| Two ends on one host clash on routes | Documented: use two namespaces or two hosts | README | Documented |

What the Linux backend does not change: the handshake, the crypto, the replay window and the
framing are the same code as the `--tun queue` demo.

Still open for the backend: a real run on Linux with root (ioctl, `ip` steps, ping through the
tunnel); the ioctl and ifreq values were checked against the `_IOW` encoding and the struct rules,
not against a kernel header on disk; Windows (Wintun) is untested.

## 7. What the tunnel does not stop

A VPN protects the bytes it carries from a network attacker. It does not protect the link, the
host, or the traffic pattern. These limits are the same as in the README.

| Attack | Stopped? | Why | Where |
|---|---|---|---|
| Flood that fills the link, or the CPU, from many sources (DDoS, Ch. 21) | No | No per-source rate limit or bandwidth cap. Cookies bound the work per source, not the total | U-D5, P-D3, U-D1 |
| Reflection or amplification through the tunnel port | Yes, by size and by rule | Every reply is smaller than its request and needs a valid mac1 | U-D4 |
| Traffic analysis: packet sizes, timing, which endpoints talk | No | Only 4-byte padding, no cover traffic, indices in clear | U-I1 |
| Relay of the handshake by an on-path attacker | No | The relay can forward and drop, but cannot read data or derive keys | H-X12 |
| Leaked responder private key used to pose as a client | Only with a PSK | Without a PSK the attacker can complete a handshake as any known client | H-X11 |
| Same-user processes, or the host, reading keys | No | Keys in env vars or files are visible to the OS account | K-I2, P-T1 |
| IPv6 that bypasses the tunnel (Linux backend) | No | The host may send IPv6 outside the tunnel | Section 6 |
| Captured INIT replayed after a server restart | Yes, only with `--state-file` (or `IOESSA_VPN_STATE_FILE`). Without it, no | Each peer's last accepted TAI64N timestamp is written to the state file (atomic: temp file, fsync, `os.replace`) before the RESP is built or sent, and loaded at start. A failed write refuses the handshake. Without the file, a startup warning is printed and a restart reopens the window: the replayer gets a RESP it cannot use, and the responder creates a pending session. The peer's endpoint does not move on an INIT (it moves on the first authenticated packet of the new session), so the replay cannot redirect the tunnel | `TimestampStore`, `Node._on_init`; `test_replayed_initiation_rejected_after_restart`, `test_state_file_holds_timestamp_before_resp_is_built`, `test_failed_state_write_sends_no_resp_and_changes_nothing`, `test_corrupted_state_file_refuses_to_load_and_is_not_reset` (test_state.py) |
| Replay protection after restart: state file deleted, rolled back, or shared | No | The check depends on the file being the latest copy. Deleting it or restoring an older copy reopens the window for INITs older than that copy. Two server processes on one file are not coordinated (the last writer wins). The operator must keep one file, on local disk, readable only by the server account | README.md, "Restart and replay state" (operator duty, not enforced in code) |
