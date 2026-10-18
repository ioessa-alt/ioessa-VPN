# Zero trust review: ioessa tunnel prototype against *Zero Trust Networks* (Gilman & Barth)

Scope: `vpn_core.py`, `vpn_server.py`, `vpn_client.py`, `vpn_keygen.py`, `README.md`, in this folder.
Read first: `THREAT_MODEL.md`, `KEY_LIFECYCLE.md`, `NETWORK_SECURITY_REVIEW.md`, `OPERATIONS_REVIEW.md`.
Book line numbers (`L###`) are lines of the extracted text, `scratchpad\zerotrust.txt`. Chapter starts:
ch1 L331, ch2 L1079, ch3 L1884, ch4 L2237, ch5 L2721, ch6 L3868, ch7 L4703, ch8 L5615, ch9 L7032, ch10 L8546.

Book coverage: ch1, ch2, ch3, ch4 and ch10 read in full. Ch5 to ch9 read in the ranges cited in the
rows only (ch5 L3108-3122, L3460-3510; ch6 L4150-4220, L4496-4510; ch7 L5296-5313; ch8 L5618-5721,
L6138-6196, L6275-6315, L6339-6368; ch9 L7032-7130, L7315-7372, L7751-7820, L8056-8100, L8258-8333).

Status key: **Met**, **Partly**, **Not met**, **Out of scope** (the book's claim is outside this
prototype's stated scope, or no such component exists by design).

Test column: the test in `test_vpn.py` / `test_tun.py` / `test_fixes.py` that covers the claim, or
**none**.

---

## 1. Verdict

**Not zero trust.** The tunnel is partly zero-trust-shaped at the transport layer: both ends
authenticate with static keys, every datagram is AEAD-checked, unauthenticated input gets silence,
session keys are short-lived, and inner source addresses are checked against a per-peer list. It has
no user identity, no device binding, no per-flow or per-request policy, no control plane, no trust
score, no credential expiry for identity keys, and no live revocation. In the book's own terms it is a
traditional VPN: a tunnel to a gateway, IP-prefix routing, and plaintext handed to the host stack
(see section 5). The book's point is that a VPN's protection stops at the concentrator: past it, traffic is no longer
protected (L975-977).

---

## 2. Chapters 1-2: core properties

| # | Claim (book) | Code location | Status | Test |
|---|---|---|---|---|
| 1.1 | Treat the network as hostile at all times (L358) | `Node.handle` (size and shape checks), `open_data`, `_on_data` | Partly: holds for tunnel traffic. Default client BYPASS sends non-protected traffic in clear (`vpn_client.py` `main`, `Peer.route`) | `test_tampered_ciphertext_rejected`, `test_forged_or_replayed_packet_does_not_roam` |
| 1.2 | Threats are always present on the network, from inside and outside (L360) | Server accepts any peer with a pinned key. No per-host or per-role check beyond `allowed_ips` | Not met | none |
| 1.3 | Being on a given network is not enough reason to trust something (L361) | Identity is the static key (`consume_initiation`, `_on_init`). Source address is not trusted (`_on_data`, roaming only after AEAD) | Met for identity. Partly for policy: TUN-mode `allowed_ips` is an address rule (see section 3) | `test_forged_or_replayed_packet_does_not_roam`, `test_roaming_updates_endpoint` |
| 1.4 | Authenticate and authorize each device, each user and each flow (L362) | Device: mutual static-key handshake. User: none. Flow: AEAD per packet, replay window, `_source_allowed` | Partly: device authenticated; no user; authorization is "key in peer table + inner source in `allowed_ips`", not per flow | `test_auth_with_correct_transcript_is_accepted`, `test_tampered_auth_message_rejected`, `test_replayed_packet_rejected`, `test_spd_protect_bypass_discard` |
| 1.5 | Policy should change over time and draw on as many data sources as it can (L363) | Policy is startup config: peer file, `--protect`, `--tun-route`, SPD, `allowed_ips` | Not met | none |
| 1.6 | Control plane grants trust in real time; data plane only accepts what it is told (L414-431) | No control plane. One process holds keys, peers, sessions and policy (`Node`, `serve`, `serve_tun`) | Not met | none |
| 1.7 | Trust from the control plane should expire and be renewed by checking in often (L1801-1804) | Sessions expire: `REKEY_AFTER_TIME` 120 s, `REJECT_AFTER_TIME` 180 s (`seal_data`, `_rekey_due`). Renewal re-checks the static key only, not any policy | Partly | `test_rekey_by_time`, `test_rekey_by_message_count`, `test_responder_can_initiate_rekey` |
| 1.8 | Hosts and network devices discard any traffic that is missing one of these controls (L967-968) | Unauthenticated datagrams dropped silently (`_on_init`, `_on_data` "unknown index"). Traffic outside the SPD is sent in clear (`BYPASS`) | Partly | `test_mac1_checked_silently`, `test_unauthenticated_floods_keep_no_state`, `test_authenticated_empty_inner_does_not_crash_server` |
| 1.9 | The endpoints themselves must do the authentication and encryption (ch9 L7072-7073) | Both endpoints run `Node`. No middlebox | Met | `test_handshake_produces_matching_sas` |
| 1.10 | Every authentication credential should have a limited lifetime (L1348-1349) | Session keys: time-boxed (row 1.7). Identity keys: no expiry, rotation by hand (`KEY_LIFECYCLE.md` section 3) | Partly (sessions met; identity keys not) | `test_rekey_by_time` (sessions only) |
| 1.11 | All trust starts with the operator (L1104); trust chains by delegation (L1120-1140) | Operator copies keys over a second channel; README fingerprint check. No delegation, no CA | Partly: fits the small static case the book allows (ch9 L7080-7081 and ch4 notes); no chain | `test_key_from_file`, `test_static_keys_are_not_in_source` (no fingerprint test) |
| 1.12 | Zero trust extends the Internet Threat Model to include compromised endpoints (L1239-1241) | `THREAT_MODEL.md` scope: network attacker. Local-process and key-file exposure are accepted (P-T1, K-I2) | Not met (endpoint compromise is out of the tunnel's model) | none |
| 1.13 | Credentials stored on disk must be protected (L1274-1276) | Key file: `load_static_private` refuses a file that group or others can access on POSIX (`_check_key_file_mode`). On Windows it prints a warning, because modes are not enforced. `vpn_keygen.py` writes mode 0600 (line 25). Env var readable by same-user processes (K-I2) | Partly. Windows modes not enforced | `test_key_from_file`, `test_missing_key_is_reported_without_value`, `KeyFileModeTests` (test_hardening.py) |
| 1.14 | Least privilege per entity and per device (L1507-1516, L1573-1578) | Per-peer `spd` and `allowed_ips`. Queue mode: `allowed_ips` defaults to `0.0.0.0/0` (`Peer.__init__`). TUN mode: every peer gets the same routes (`vpn_server.py`), so the server refuses to start with two or more peers whose lists overlap (`check_allowed_ips_disjoint`) | Partly: per-peer in the data model; in TUN mode, one peer per server until per-peer routes exist | `test_server_drops_packets_with_no_matching_peer`; `test_overlapping_allowed_ips_are_detected_without_printing_keys` (test_hardening.py) |
| 1.15 | Variable trust, risk score per request (L1582-1613, L1667-1683) | None | Not met | none |
| 1.16 | Every flow audited with identity (L969-971) | Events name the source address only (`handshake from {src}`). No peer name, no timestamps (`OPERATIONS_REVIEW.md` 3.1) | Not met for identity. Partly for event logging | `test_rejection_counter_counts_only_inbound_refusals` |
| 1.17 | Data-plane to control-plane traffic needs encryption and authentication through a private PKI (L1786-1788) | No control plane, no PKI. Raw keys pinned (`NETWORK_SECURITY_REVIEW.md` section 2) | Not met (deliberate, per the review) | none |

---

## 3. Identity and trust (ch 3-8): actor map

| Actor | Identity in the tunnel | Book's model | How trust is set up | What the tunnel trusts that the book says it should not |
|---|---|---|---|---|
| Client device | X25519 static key. Private key: `--key-file` or env. Public key pinned on server (`--peer-key-file`, `add_peer`) | Device identity bound to hardware: a software key that is not tied to the hardware does not really identify the device (L3118-3122). X.509 suits devices rather than people (L6187-6188) | Responder decrypts the initiator's static key and checks the peer table (`consume_initiation`, `_on_init`). Timestamp AEAD proves possession of the static private key | A raw key file. No TPM, no expiry, no posture check. Whoever has the key has the device. One key gets every route in `allowed_ips` |
| Server | X25519 static key. Pinned on client: every configured key is tried at once (`handshake_any`, `vpn_client.py`); the one that answers is used (fixed in the second pass, `KEY_LIFECYCLE.md` gap 2) | Mutual authentication is required (L6353-6354) | Initiator checks the responder's empty AEAD keyed through the responder's static key (`consume_response`) | No CA, so a changed key is only caught by fingerprint over a second channel |
| User | None | User identity is the first of three components (L918-919) | n/a | Nothing. A person is "whoever is at the keyboard with the device key" |
| Application or process | None | Each workload is authorized separately (L5308) | n/a | Any process that can read the key file or env var is the device (K-I2) |
| Optional PSK | One node-wide 32-byte secret, all peers (`Node.psk`, `load_psk`). Mixed into the chain key and mac1 key (`_init_chain`, `_mac1_key`) | The book sees PSKs as secrets made for people to memorize and advises firmly against them (L6181-6186). Multiple secrets in different places are good (L1336-1341) | Optional (`--use-psk`), off by default | One secret shared by every peer (K-X1). A PSK holder still needs a static key, so the PSK alone does not admit anyone. A leaked PSK does weaken the extra layer for all peers |
| `allowed_ips` | Per-peer prefix list. Queue mode: `0.0.0.0/0`. TUN mode: the `--tun-route` prefixes, the same for every peer | Using an IP address or a physical location as the identifier does not protect a resource well enough (L911-913) | Checked after AEAD on every inbound packet (`_source_allowed`). Also picks the outbound peer (`_pick_peer`) | IP address as authorization. Verified (section 7, check C): with two peers in TUN mode, peer 2 can send with source `10.8.0.2`, which belongs to peer 1 |

**How the tunnel establishes trust.** The operator distributes public keys out of band and checks
fingerprints over a second channel. Each side pins the other's key. A 1-RTT Noise IK handshake proves
both static keys and derives ephemeral transport keys. Every data packet is then authenticated with
those keys. The source address is used only after authentication, for roaming. Inner packets are
checked against `allowed_ips`. Nothing else is consulted: no directory, no policy, no device state.

**Trust the book would say it should not have:** (a) long-lived identity keys with no expiry or
hardware binding; (b) one PSK shared by all peers; (c) inner IP addresses as identity; (d) plaintext
key material on disk and in env vars (the book's credentials stored on disk, L1274-1276); (e) the host the
key runs on, with no posture check; (f) the replay state, which resets on restart unless `--state-file` is used (section 7,
check D).

---

## 4. Chapters 3-8: other components

| Ch | Claim (book) | Code location | Status | Test |
|---|---|---|---|---|
| 3 | Agent = user + application + device, authorized as a whole (L1919-1928, L1993-2002) | None. Only the device key is checked | Not met | none |
| 3 | Agents are for authorization only and take no part in authentication (L2020-2021) | Authentication and authorization are the same step in `_on_init` (key in peer table) | Not met | none |
| 3 | Do not cache an agent or the outcome of an authorization request (L2034-2035) | Session holds authorization for up to 120 s with no re-check (`Peer.current`) | Partly: flow-level caching; request-level is not implemented | `test_rekey_by_time` |
| 3 | Withdraw authorization before you withdraw credentials (L2044) | `Node.remove_peer` drops keys and sessions. Nothing calls it in production. Revocation is a restart (`KEY_LIFECYCLE.md` section 2) | Partly: library only | `test_removed_peer_session_is_dropped`, `test_removed_peer_cannot_handshake_again` |
| 4 | Four components: enforcement, policy engine, trust engine, data stores (L2261-2276). Be wary of designs that merge these roles into one (L2271-2276) | One process does all four | Not met | none |
| 4 | Enforcement close to the workload, because trust collects in whatever sits behind the enforcement point (L2346-2350) | One endpoint per host, in front of a whole prefix (`--tun-route`) | Partly | none |
| 4 | Policy engine as a separate process (L2377-2383) | Policy is `Node` state in the tunnel process | Not met | none |
| 4 | Policy kept in version control and reviewed (L2404-2407) | Policy is CLI flags and files. Not in a repo | Not met (operator practice only) | none |
| 4 | Trust engine and data stores (L2515-2557, L2617-2673) | None | Not met | none |
| 4 | Every flow gets a decision (L2243-2244) | Per packet: AEAD, replay, `_source_allowed`. No decision beyond SPD and `allowed_ips` | Partly | `test_replayed_packet_rejected`, `test_out_of_window_sequence_rejected` |
| 5 | Device identity bound to hardware (TPM) (L3115-3122) | None | Not met | none |
| 5 | Device rotation and age as a trust signal (L3460-3510) | Keys are never rotated automatically. No device age | Not met | none |
| 5 | Running instances individually authorized (L5302-5308) | Key-based only; no software state | Not met | none |
| 6 | The client's authorization has to be re-checked often (L4197-4198) | Rekey every 120 s re-runs the handshake with the same key | Partly | `test_rekey_by_time` |
| 6 | A challenge-response exchange reduces the risk of replay (L4498-4499) | Timestamped INIT, counters and a 64-packet window. No challenge-response. INIT replay is refused in-process; across a restart only with `--state-file` (section 7, check D) | Partly | `test_replayed_initiation_rejected`, `test_old_timestamp_rejected`, `test_replayed_packet_rejected` |
| 6 | User authentication (three factors, L4212-4219) | No users | Out of scope | none |
| 7 | Application identity and per-app authorization (ch7 read only at L5296-5313) | Tunnel carries IPv4 datagrams; no application identity | Out of scope | none |
| 8 | Encryption comes at no extra cost once packets are authenticated (L5674-5679); everything unauthenticated is dropped with no reply at all (L5691-5692) | Silent on bad mac1 (`_on_init`). Cookie reply only with a valid mac1, under load. UDP port stays open | Partly: no reply to unauthenticated packets, but no SPA-style hiding of the port | `test_mac1_checked_silently`, `test_unauthenticated_floods_keep_no_state` |
| 8 | Forged or replayed messages must be refused (L5641-5643) | AEAD on data; per-peer TAI64N timestamp on INIT, held in memory, or in the state file with `--state-file` | Partly: a restart resets the INIT check unless `--state-file` is used | `test_replayed_initiation_rejected` (in-process); `test_replayed_initiation_rejected_after_restart` (test_state.py) |
| 8 | Tunnel mode goes against the zero trust architecture (L6302-6303); transport mode suits it well (L6310-6311) | Tunnel mode shape: whole inner IPv4 datagram encapsulated, then written to the host stack in plaintext (`serve_tun`, `run_tun`) | Not met (book's view) | `test_host_packet_crosses_the_tunnel_both_ways` |
| 8 | IKE: X.509 preferred, PSK firmly discouraged (L6181-6188) | Raw keys; optional node-wide PSK | Not met (keys), Partly (PSK is optional) | `test_psk_mode_handshake_completes`, `test_wrong_psk_fails_authentication` |
| 8 | Unprotected traffic amounts to a privileged zone (L5659-5673) | Client default: only `--protect` prefix is tunnelled; the rest is BYPASS, in clear | Not met for default config | `test_spd_protect_bypass_discard` |

---

## 5. Chapter 9: case-study fit

**Verdict: traditional VPN in shape.** The tunnel is a host-to-gateway (or host-to-host) IP tunnel
with prefix routing, static keys, and plaintext in the host stack after decryption. The book's
prioritized list (L7070-7082) gives the tests:

- MUST: authenticate every flow before handling it. Met for tunnelled flows. Not met for BYPASS flows.
- MUST: list every flow, so access can be enforced. Partly: prefixes are enumerated, flows are not.
  No flow log.
- SHOULD: do not depend on a public PKI for authentication. Met, trivially: there is no PKI.
- SHOULD: scan, patch and replace devices on a schedule. Not met.
- SHOULD: strongest suites. Met: X25519, ChaCha20-Poly1305, BLAKE2s, no negotiation.

**Case studies.** BeyondCorp (L7789-7799) does away with the privileged corporate network altogether.
Access goes through an access proxy per application, based on device and user, and the VPN is phased
out (L8079-8092). PagerDuty (L8276-8333) enforces per host, from configuration management, with
role-based allowlists that drop anything not on the list. The tunnel has one part of PagerDuty's
design (a per-peer allowlist) but it is keyed by IP and funnelled through one gateway. It has none of
BeyondCorp's pieces.

**What it would need to be a zero trust component (not built):** a policy engine separate from the
tunnel process; device identity bound to hardware, with certificates from a private CA and short
lifetimes; user identity and an agent (device + user) for each request; per-flow or per-application
enforcement close to the workload; authentication and encryption on bypass traffic too; per-peer
addresses, not shared routes; revocation pushed at runtime; logs with identity; transport mode in place
of the host-stack tunnel. The book itself treats tunnel mode as a transitional tool (L6312-6315).

---

## 6. Chapter 10: adversarial view

The book's summary: zero trust stops some attacks well, but for others the most it can do is detect
them (L8879-8881).

| Book weakness | Tunnel status | Evidence |
|---|---|---|
| **Identity theft** (L8580-8613). an attacker should have to steal two identities or more (L8605-8608) | **Exposed.** One static key per device. A stolen client key gives every route its `allowed_ips` allows, with no second factor. In TUN mode that is the shared tunnel prefix, and the stolen peer can also claim other peers' addresses (check C). Revocation has no runtime path (`KEY_LIFECYCLE.md` section 2) | `remove_peer` exists, is tested, and is not called by any CLI path |
| **Distributed DoS** (L8615-8654): zero trust alone does little against it | **Partly mitigated.** Unauthenticated input costs no state (`_on_init`); mac1 before DH; cookie under load. No per-source rate limit, so a volumetric flood still costs CPU and bandwidth (THREAT_MODEL P-D3, U-D1) | `test_unauthenticated_floods_keep_no_state`, `test_mac2_checked_under_load` |
| **Pre-authentication / darkening** (L8626-8634, L5691-5716) | **Partly.** Silent on bad mac1, but the UDP port is open and reachable. No deny-all plus signed knock | `test_mac1_checked_silently` |
| **Endpoint enumeration** (L8664-8690). it keeps traffic confidential but does not make it private (L8674-8677) | **Out of scope for privacy; confidentiality met.** Outer addresses, ports, sizes, timing and indices are visible (THREAT_MODEL U-I1, not done) | `test_identity_hidden_on_wire` (initiator key only) |
| **Untrusted computing platform** (L8691-8713). Encrypt persistent data and swapped memory | **Exposed.** Key file is plaintext on disk, mode ignored on Windows. No memory zeroing (Python). Env var readable by same-user processes | THREAT_MODEL K-I2, K-I3 |
| **Social engineering** (L8714-8736) | **Out of scope.** One partial control: the fingerprint check (README) against key substitution | none |
| **Physical coercion** (L8737-8765). Keep the least sensitive data exposed to one person; replace devices and credentials on a regular cycle (L8763-8764) | **Exposed.** Whoever holds the key holds the tunnel. No rotation schedule (`KEY_LIFECYCLE.md` gap 4). In TUN mode one key's scope is the whole shared prefix | section 3 |
| **Invalidation** (L8775-8815). a session cannot be cut off faster than the slowest polling interval allows (L8812-8815) | **Exposed.** Revocation is a restart. Session expiry is enforced by `poll()`. `serve()` and `serve_tun()` now run it once per tick (1 s) even under steady traffic (fixed in the second pass). The receive path still has no age check, so an old session can decrypt for up to one tick after its limit (check A) | `test_rekey_by_time` covers the sender; `TimersUnderLoadTests` (test_hardening.py); no per-packet receive-age test |
| **Control plane security** (L8818-8873) | **Out of scope / not applicable.** There is no control plane. The operator's shell and key files are the only "policy" | none |

**Weak points the book's list does not name, found in this review:**

- Replay state is in memory unless `--state-file` is used. After a server restart without it, a captured
  INIT is accepted again (check D). The replayer gets no keys, and since the second pass an INIT no longer
  moves the endpoint (`test_hardening.py`).
- Shared `allowed_ips` in TUN mode (check C), which is the same as the "identity theft" row above. Fixed in
  the second pass: the TUN server refuses two or more peers with overlapping lists at startup. Queue mode
  still uses the default any-source list, which is a demo setting.
- Taking a key out of the peer file does not end its live session. Only `Node.remove_peer` does, and
  it runs in-process only. Nothing calls it, so the session lives until the server restarts.

---

## 7. Scratch checks (run here, not in the tree)

Scripts in `scratchpad\gap_check.py` and `scratchpad\replay_restart_check.py`. They import `vpn_core`
and do not modify it.

- **A. Receive-side session age (no poll).** A packet sealed at t=1000 was delivered at t=1600 with no
  `poll()` on the receiver. It was accepted. With `poll()` run first (as `serve_tun` does each loop), it
  was dropped as "unknown index". Cause: `_on_data` and `open_data` do not check `Session.created`;
  only `_expire` (in `poll`) does.
- **B.** Same packet with `poll()` run first: dropped as "unknown index". This is the second half of A.
- **Superseded (second pass):** `serve()` and `serve_tun()` now run `poll()` once per tick, so the expiry in A
  applies within one tick. The receive path still has no age check.
- **C. Shared allowed_ips.** Two peers, both with `allowed_ips = 10.8.0.0/24`. Peer 2 presenting inner
  source `10.8.0.2` (peer 1's address) passes `_source_allowed`. **Superseded (second pass):** `check_allowed_ips_disjoint` now refuses this configuration at TUN startup, and the receive path refuses a source outside the peer's own list (`test_hardening.py`, `SourceClaimTests`).
- **D. INIT replay after restart.** Original INIT accepted. Same-process replay refused
  ("handshake failed"). After a restart (new `Node`, same keys), the replayed INIT was accepted, and
  `peer.endpoint` moved to the replayer's address. **Superseded (second pass):** the endpoint no longer moves on an INIT (`test_replayed_init_after_restart_does_not_move_endpoint`). Restart reopening replay is fixed only with `--state-file` (`test_state.py`).

---

## 8. Changes made

| File | Change |
|---|---|
| `tunnel\ZERO_TRUST_REVIEW.md` | New. This file |
| `tunnel\README.md` | Test count "123 tests pass" changed to "138 tests pass". The full suite ran at 138, all passing, on the current tree |

First pass: no code changed. Second pass: `vpn_core.py`, `vpn_server.py` and `vpn_client.py` changed for the
hardening gaps (source claims, endpoint on INIT, timers, server-key overlap, key-file modes), and
`test_hardening.py` is new. Wire format, handshake, crypto and dependencies unchanged. `tunnel\analysis\` not touched.

**Stale claims in other docs, updated in the second pass:**

- `THREAT_MODEL.md` R-S1: expiry is within one tick, because `poll()` now runs on a fixed schedule.
- `THREAT_MODEL.md` U-D3: partial. In-process only, and across a restart only with `--state-file`.
- `THREAT_MODEL.md` P-E1 and D-E1: updated (root for `--tun linux`; the Linux TUN path exists).
- `KEY_LIFECYCLE.md` gap 2 (server-key overlap): fixed. Its test count is updated.
- `CRYPTO_REVIEW.md` F9 and `SECURITY_ENGINEERING_REVIEW.md` (replay across restart, endpoint on INIT):
  marked superseded or fixed.

---

## 9. Not verified

- Ch5 to ch9 read in the ranges listed at the top, not in full. Rows relying on other passages are
  not claimed.
- No live network test. Loopback and in-process checks only.
- Attack on a real stolen key (check C and the identity-theft row) is by code reading and the scratch
  checks, not by a penetration test.
- Whether `serve()` under real traffic starves `poll()` (check A): fixed in the second pass. It is tested
  with a fake socket and clock (`TimersUnderLoadTests`), not on a real socket under load.
- The book's ch10 text is quoted as read. The book was not checked against a printed copy.
