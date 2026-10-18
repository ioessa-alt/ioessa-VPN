# WireGuard comparison: ioessa VPN prototype

Scope: read-only review of `vpn_core.py`, `vpn_server.py`, `vpn_client.py`, `test_vpn.py`, `README.md` in this folder, compared against Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel" (NDSS 2017). No code was edited.

Citation conventions:
- "paper L###" is a line number in the extracted text file `%LOCALAPPDATA%\Temp\claude\<project>\698fab37-9a7d-4984-976c-fd9ed4bcc2b6\scratchpad\wireguard.txt` (a local scratch copy, not in the repository). Section names are the paper's own headings.
- Code citations are `file:line` in this folder.

Line numbers are from the current files and will drift as the other agent edits them. Re-check before applying anything.

**Status note (finalization pass).** This is a snapshot of the gaps as first written. Most of the
gaps below are now closed in code, each with a test, so the gap text and the "Recommended order" list
are history. Closed: G1 and G10 (mac1 and cookie replies; `test_mac1_checked_silently`,
`test_cookie_reply_roundtrip`, `test_mac2_checked_under_load`); G2 (time-based rekey; `test_rekey_by_time`);
G3 (inbound source check; `test_claimed_source_is_refused_and_endpoint_does_not_move`); G4 (retry with
backoff and cap; `test_gaps_double_then_cap_and_attempt_is_bounded`); G5 (roaming after AEAD check;
`test_roaming_updates_endpoint`, `test_forged_or_replayed_packet_does_not_roam`); G6 (keepalive;
`test_keepalive_sent_after_idle_period`); G7 and G8 (identity hiding and TAI64N replay check;
`test_identity_hidden_on_wire`, `test_replayed_initiation_rejected`); G9 (one round trip, Noise IK); G12
(64-bit counter in the transport header). Still open: the bitwise-identical retry rule (RFC7296_REVIEW.md),
G13 (no memory zeroing; Python limit), and the paper-vs-prototype hash and KDF differences (BLAKE2s is now
used in the handshake, see README). Statements in the body that say "no roaming", "no keepalive",
"no tests for rekey" or "client crashes on timeout" describe the old code.

---

## 0. Summary of the design position

The prototype is an IKE-style, PSK-authenticated ESP-over-UDP tunnel. It follows Kurose & Ross section 8.7 (SAD/SPD, ESP tunnel mode, two-phase IKE), not WireGuard. The shared pieces are the primitives (X25519, ChaCha20-Poly1305, HKDF), a fixed suite, a per-direction key split, and a bitmap replay window.

The main divergences from WireGuard are:
1. The handshake takes 2 round trips (four messages), where the paper's is 1-RTT (paper L129, L392-402, L659-665).
2. Every well-formed INIT is answered, and per-INIT state and DH work are done before any authentication (paper section V-A, V-C).
3. There is no cookie or mac1 mechanism.
4. The only authenticator is a single shared PSK. There are no per-peer static keys, so the paper's cryptokey routing (section II) cannot be implemented as written.
5. The endpoint is pinned at handshake time. There is no roaming (paper section II-A).
6. Rekeying is count-based only, and only on the sender side. There is no time-based rekey (paper section VI-B, VI-C).
7. There is no keepalive (paper section VI-E).

---

## 1. Matches

| # | Paper | Prototype | Where | Notes |
|---|---|---|---|---|
| M1 | One fixed suite, no negotiation (paper L121-123) | X25519, ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, all hard-coded. No negotiation. | `vpn_core.py:33-39`, `:146`, `:169`, `:312`, `:320` | Hash differs from the paper (BLAKE2s, paper L129-133). See gap G11. The docstring's "downgrade" claim is not in the paper, which justifies no agility by the cost of updating endpoints (paper L122-125). |
| M2 | Fresh ephemeral X25519 per handshake, gives PFS (abstract L17-18; paper section V-D2 L676-707) | Fresh `X25519PrivateKey.generate()` on each side for each handshake. | `vpn_core.py:399`, `:436` | Holds for each session. The lifetime problem is in G2. |
| M3 | Per-direction, per-purpose key derivation (paper section V-D5 L751-757) | Four separate HKDF outputs labeled by direction and purpose, with both SPIs in the info string. | `vpn_core.py:334-336`, `:339-353` | Good match. |
| M4 | Handshake messages authenticated over the transcript, with a role label (paper section V-D2/V-D3 hash chain L692-707, L729-733) | HMAC-SHA256(PSK, role `"I"`/`"R"` \| transcript), with the tag encrypted under the IKE key. | `vpn_core.py:379-383`, `:415`, `:456`, `:390-391` | Role label prevents reflection. Tests at `test_vpn.py:236-262` cover this. |
| M5 | Message type byte inside the header (paper L574-575) | `IKE_MARK` plus type byte checked in `_check_header`. | `vpn_core.py:372-376` | Good. |
| M6 | AEAD tag covers ciphertext; paper's transport AEAD uses empty AD (paper L776) | The ESP header is authenticated as AD, so the SPI and seq are covered. | `vpn_core.py:146`, `:169` | Stronger than the paper. Keep it. |
| M7 | Nonce unique per key (paper L629-632, counter nonce) | `salt(4) \| 0(4) \| seq(4)`, fresh key per SA. Uniqueness depends on seq never repeating. | `vpn_core.py:124-129` | Width is 32-bit, not 64-bit. See G12. |
| M8 | Sliding window, bitmap, updated only after authentication (paper L795-802, RFC 2401 App. C / RFC 6479) | 64-packet bitmap window. Check is read-only, update happens after AEAD verify. | `vpn_core.py:77-105`, `:165-167`, `:172` | Tests at `test_vpn.py:270-284`. Matches the paper's receive order (paper section III step 2). |
| M9 | Drop unauthenticated junk with no reply (paper section V-A, L411-424), partial | Length and header checks run before any reply. A malformed datagram gets no reply and no state is kept. | `vpn_server.py:45-46`, `:52-54`; `vpn_core.py:372-376` | Partial. A well-formed INIT still gets a reply (G1). |
| M10 | Bounded resources (paper section VII goal of not allocating memory dynamically, L979-981) | `MAX_ESP`, `MAX_INNER`, `MAX_PENDING` with oldest-eviction. | `vpn_core.py:47-49`; `vpn_server.py:21-30` | Partial. Memory is bounded, CPU is not (G1). |
| M11 | Generic handshake failure, no oracle (paper: not stated; standard practice) | Single `HS_FAIL` string for all handshake errors. | `vpn_core.py:362`, `:365-369` | Good. |
| M12 | Pre-shared key is 32 bytes and comes from outside the code (paper section V-B L448-474) | `IOESSA_VPN_PSK`, hex, at least 32 bytes. Never printed. | `vpn_core.py:57`, `:298-308`, `:120-121` | Paper uses PSK as an optional extra layer. Here it is the only authenticator. See G7. |
| M13 | Demux on the first bytes of the datagram (paper L297-299, type byte) | First four bytes are either `IKE_MARK` or a non-zero SPI. | `vpn_server.py:47`, `:74`; `vpn_core.py:54` | Matches the NAT-T idea. Note that `IKE_MARK` plus type byte is a fixed fingerprint. The paper's type bytes are also fixed, so this is not a regression. |
| M14 | Route lookup before encryption, drop if no match (paper III step 2, L274-278) | SPD is consulted on the destination. The default is DISCARD. | `vpn_core.py:228`, `:237-258` | Destination side only. There is no inbound source check (G3). |
| M15 | Keys never logged (paper: n/a) | `SA.__repr__` omits the key. | `vpn_core.py:120-121` | Good. |

---

## 2. Gaps, ranked by impact

Impact is for this prototype's threat model and use. The README says it is loopback-only and not for real traffic (`README.md:8`, `:46`). Ranking reflects impact if it were run on a real network with more than one peer.

Scope labels:
- **In scope**: worth doing in this prototype.
- **Deferred**: in scope later, once the real-network or multi-peer work starts.
- **Out of scope**: not worth copying here. Reason given.

### G1. No DoS protection on the responder (no mac1, no cookie, state and CPU before auth)

- **WireGuard:** Every message carries `msg.mac1`, keyed by the responder's public key and optional PSK. The responder silently drops anything without a valid mac1 (paper section V-C L515-528, V-D4 L746-747). Under load, a valid-mac1 message without a valid mac2 gets a cookie reply, which is encrypted and bound to the source IP (paper section V-C L488-500, L529-545, V-D7 L803-832). Responder keeps no state before authentication (paper section V-A L411-424).
- **Prototype:**
  - On any datagram with the first four bytes zero and type `T_INIT`, the server constructs an `IKEResponder`. That generates an X25519 key, a nonce, and an SPI before any length check (`vpn_server.py:50-51` calls `IKEResponder(psk, addr)`, and `vpn_core.py:434-438` does the work). The length check is only in `handle_init` (`vpn_core.py:441`), after the work is done.
  - A well-formed 53-byte INIT gets a full DH and a reply of the same size (`vpn_server.py:52-54`, `vpn_core.py:444-446`). The paper says the response must be smaller than the initiation to avoid amplification (paper L737-738). Here they are equal.
  - Unauthenticated state is stored in `pending` (`vpn_server.py:53`, `:21-30`). The test `test_vpn.py:320-337` asserts that a spoofed flood evicts legitimate half-open handshakes.
- **Risk:** CPU exhaustion from unauthenticated INITs (paper section VII-B also notes that DH work must not starve the CPU, L1048-1054). Reflection to spoofed addresses. Eviction of legitimate pending handshakes by spoofed INITs from the victim's own address.
- **Smallest change:**
  1. Check `len(data) == 5 + 48` in `serve()` before constructing `IKEResponder`. This is a quick win and needs no wire change.
  2. Append `mac1 = HMAC-SHA256(PSK, b"mac1" \| INIT body)[:16]` to INIT. Verify with `hmac.compare_digest` before any DH. Silently drop on mismatch. Store `pending` only after mac1 is valid. Because the PSK is the only key, this is the paper's mac1 with the PSK as the key. Callers without the PSK get no reply and no state.
  3. Cookie reply (mac2 and the AEAD-wrapped cookie, paper L529-550, L803-832) can come later. It needs rotating secrets and a per-address cookie. It is optional for a prototype.
- **Scope:** In scope. Steps 1 and 2 are small, but step 2 changes the INIT format and the test helpers that build INITs (`test_vpn.py:224`, `:313-314`, `:326`). The eviction test must be rewritten to check "no reply and no state without mac1". Step 3 is medium and optional.

### G2. Rekey is count-based only, sender-side only, and drops old keys at once

- **WireGuard:** Rekey after 120 s or 2^64-2^16-1 messages, whichever first (paper section VI-B L869-874, VI-A L855-858). Reject sending after 180 s (paper L881-886). The responder rekeys with 2x Rekey-Timeout slack so both sides do not rekey at once (paper L876-881). The previous session is kept for in-flight packets (paper section VI-C L898-905), and the session is discarded after 3 x Reject-After-Time (paper L906-909).
- **Prototype:**
  - `SA` has no creation time (`vpn_core.py:109-121`). `esp_encapsulate` only checks `seq >= seq_limit` (`vpn_core.py:136-137`), so the only rekey trigger is sequence exhaustion (`REKEY_MARGIN`, `vpn_core.py:51`).
  - The client rekeys only when `RekeyRequired` is raised (`vpn_client.py:61-65`, `:93-95`). The server cannot rekey on its own. When the server's outbound seq is exhausted, `serve()` logs "reply not sent" and drops the reply (`vpn_server.py:98-99`).
  - When a new AUTH_I arrives from the same address, the old SA is removed from `by_spi` at once (`vpn_server.py:61-63`). Packets still in flight on the old SPI are dropped.
  - Consequence: PFS is only per handshake, and a session can live for about 2^32 packets (roughly 6 TB at 1400-byte packets, or many hours at normal rates) before any rekey.
- **Risk:** Long-lived keys weaken PFS. A key leak exposes the whole session. In-flight loss during each rekey. No recovery on the server side if it hits the sequence limit before the client rekeys.
- **Smallest change:**
  1. Add `created: float = field(default_factory=time.monotonic)` to `SA`. In `esp_encapsulate`, raise `RekeyRequired` when `time.monotonic() - sa.created > 120`. Keep the count check.
  2. In `vpn_client.py`, the existing `RekeyRequired` handler already re-handshakes. Calling `connect()` on time also refreshes the server's outbound SA, because the new handshake creates both directions. So a client-driven time rekey covers the server direction without the server initiating.
  3. In `vpn_server.py`, keep the old inbound SPI in `by_spi` for about 5 s after a replacement (for example, store `(tunnel, expires)` and sweep it).
- **Scope:** In scope. Step 1 is small. Step 3 is small to medium. Server-initiated rekey (paper's symmetric roles, section VI-D L910-924) is large and out of scope for the first pass.

### G3. No inbound source-address check (cryptokey routing is half-implemented)

- **WireGuard:** After decryption, the inner source IP must route back to the same peer in the cryptokey routing table, or the packet is dropped (paper section II L180-187, section III step 4 L310-318). This is one table used for both sending and receiving, so it works like reverse-path filtering (paper L321-336).
- **Prototype:** `Tunnel.route()` is used only on send (`vpn_core.py:237-245`, `:250`). `Tunnel.receive()` returns whatever the peer sent, with no source check (`vpn_core.py:260-267`). `vpn_server.py:79-99` logs it and echoes back to the inner source. Any holder of the PSK can send traffic claiming any source IP.
- **Risk:** Spoofing of inner source addresses by an authenticated peer. With one shared PSK, every peer is equally trusted, so this matters the moment there is more than one peer or any firewall that trusts tunnel source addresses.
- **Smallest change:** Give `Tunnel` an allowed-source list (or reuse the SPD list). After `esp_decapsulate`, check that the inner source is in the list for that SA's peer. Drop with a new reason string such as `"source not allowed"`. Add one unit test: a valid tag with a forbidden inner source is rejected.
- **Scope:** In scope. Small. Full per-peer cryptokey routing (identity per peer) is the larger job in G7.

### G4. Handshake has no retransmission and the client crashes on timeout

- **WireGuard:** After sending an INIT, if no RESP arrives within Rekey-Timeout (5 s), a new INIT with new ephemerals is sent. This repeats for up to Rekey-Attempt-Time (90 s) (paper section VI-D L910-924). The paper says exponential backoff is future work (L922-924).
- **Prototype:** `connect()` sends one INIT and waits once. `_recv_from` raises `socket.timeout` (`vpn_client.py:31`), which `connect()` does not catch (`vpn_client.py:45-56`). `main()` does not catch it either (`vpn_client.py:88`). A lost packet becomes a traceback, not a retry. `README.md:46` acknowledges this.
- **Risk:** Any single UDP loss fails the connection. Unhandled exception in the client.
- **Smallest change:** In `connect()`, loop for up to 90 s, creating a new `IKEInitiator` each attempt and sending INIT at most once every 5 s. Catch `socket.timeout` and report a clean error. Also send a fresh INIT, not a re-sent old one, so the paper's rule of fresh ephemeral keys per attempt holds.
- **Scope:** In scope. Small.

### G5. No roaming: endpoint pinned at handshake time

- **WireGuard:** The endpoint is updated to the outer source address of the latest authenticated packet (paper section II-A L219-225, section III step 3 L307-309). Peer can roam between networks. The paper notes an active attacker can change addresses but cannot decrypt or modify payloads (L258-263).
- **Prototype:** `SA.peer` is fixed at handshake (`vpn_core.py:113`, `:425-426`, `:458-459`). `esp_decapsulate` rejects any source that differs (`vpn_core.py:160-161`). The server keys sessions by address (`vpn_server.py:36`, `:61`, `:67`), so a changed address leaves the session unusable until a new handshake.
- **Risk:** NAT rebinding, Wi-Fi to cellular, or any port change breaks the tunnel. Recovery needs a new handshake, which needs the client to notice.
- **Smallest change:** Remove the pre-auth endpoint check (or keep it only as a log hint). After `esp_decapsulate` succeeds, set `sa.peer = src`. Update the server's `sessions` key to match. Important: update only after the tag verifies, or forged packets can move the endpoint. Add one test: a forged packet from a new address does not move the endpoint, and a valid one does.
- **Scope:** In scope once the prototype runs on a real network. Deferred until then. The loopback demo does not exercise it. Small.

### G6. No keepalive

- **WireGuard:** Passive keepalive: a zero-length inner packet (16-byte tag only) is sent after Keepalive-Timeout (10 s) with no outgoing data, in reply to authenticated traffic only (paper section VI-E L925-947). Dead-peer detection uses the same timer (L948-957). Persistent keepalive is optional, for NAT only (paper L253-256). NAT is primarily handled by roaming (G5).
- **Prototype:** None. `vpn_server.py:91-99` only echoes. A zero-length inner packet is rejected by `describe()` as "not IPv4" (`vpn_core.py:209-210`, `vpn_server.py:86-89`). `test_vpn.py:288-308` asserts that exact drop, so a keepalive change needs that test updated.
- **Risk:** NAT mappings expire and the tunnel goes silent with no detection. Dead peers are not noticed.
- **Smallest change:** Let `esp_encapsulate(sa, b"")` produce a keepalive (it already works, since the padding path handles 0 bytes). On receive, treat a zero-length plaintext as a keepalive before `describe()`, and send one after 10 s of silence following authenticated traffic. Update the test.
- **Scope:** Deferred. Only matters on a real network. Small.

### G7. No per-peer identity and no identity hiding of static keys

- **WireGuard:** Each peer has a long-term Curve25519 static key. Its public key is the identity. The initiator's static key is encrypted in the first message (paper section V-D2 L703) and its public key is used for routing (section II). The paper compares its identity hiding to SIGMA's (paper L409).
- **Prototype:** There are no static keys. All peers share one PSK (`vpn_core.py:57`, `:298-308`). The AUTH tags and SPIs are encrypted under IKE keys (`vpn_core.py:415-416`, `:456-457`), so a passive observer cannot see them. That is a partial match. The server cannot tell peers apart, so `sessions` is keyed only by address (`vpn_server.py:36`).
- **Risk:** Any PSK holder can impersonate any other peer. Compromising one client compromises every client. There is no basis for per-peer policy, so G3 cannot be complete.
- **Smallest change:** There is no small change. Options are (a) per-peer PSKs keyed by a peer ID sent in clear (leaks identity, but is simple), or (b) per-peer static X25519 keys with a Noise-IK-style first message (paper section V-D2). Option (b) is the paper's design and is large.
- **Scope:** Out of scope for the current prototype. Reason: it needs a key-distribution design, and the prototype's stated goal is learning SA/SPD mechanics (README L3-6). Revisit before any multi-peer use.

### G8. No handshake replay protection (timestamp)

- **WireGuard:** A 12-byte TAI64N timestamp, encrypted and authenticated in the first message, is kept per peer. The responder discards any message not newer than the last one seen (paper section V-A L428-447). This stops an attacker from replaying an old INIT to make the responder regenerate its ephemeral and kill a live session.
- **Prototype:** No timestamp or counter. The responder does not kill live sessions on replay, though. Sessions change only when a valid AUTH_I arrives (`vpn_server.py:55-68`). A replayed INIT creates a `pending` entry and a reply, but the replayed AUTH_I cannot verify because it is bound to the old ephemerals (`vpn_core.py:448-460`). So a replay cannot replace a live session, which I checked by reading the code and did not test. The remaining cost is DH work and pending churn, which G1 addresses.
- **Risk:** Low today. Replay costs CPU and evicts `pending` entries, but does not hijack.
- **Smallest change:** Add an encrypted counter or timestamp to AUTH_I. Keep a per-peer high-water mark. This needs a stable per-peer identity, so it depends on G7. Keying the mark by source address would be weak, since addresses change (G5).
- **Scope:** Deferred. Depends on G7 and G5. Not needed while the prototype is loopback-only.

### G9. Handshake takes 2 round trips, not 1

- **WireGuard:** 1-RTT. The initiator can send transport data immediately after receiving RESP (paper L129, L392-402, L659-665, L848-849). The paper's design is a single round trip built on Noise IK (abstract L14-15).
- **Prototype:** Four messages, INIT, RESP, AUTH_I, AUTH_R (`vpn_client.py:47-51`, `vpn_core.py:387-391`), so data waits for two round trips. The extra round trip exists because PSK authentication needs the initiator's SPI and tag sent after phase 1.
- **Risk:** Extra latency on connect and on every rekey. More handshake state on the responder (`pending` must survive two messages).
- **Smallest change:** Not small. One option is to move the PSK tag into INIT/RESP. That needs the responder's tag in RESP, which carries less information, so it changes the security argument. Think it through before changing it.
- **Scope:** Out of scope for now. The design is coupled to G7. Reason: the cost is one RTT per handshake, which does not matter for a learning prototype.

### G10. No cookie reply under load (part of G1)

Covered in G1 step 3. Listed separately because the paper treats it as its own mechanism (paper section V-C, V-D7, VI-F). Scope: optional, medium, after G1 steps 1-2.

### G11. Hash and KDF differ from the paper (BLAKE2s vs SHA-256)

- **WireGuard:** BLAKE2s for hashing, HMAC, and HKDF (paper L129-133, L633-637).
- **Prototype:** SHA-256 for HMAC and HKDF (`vpn_core.py:311-320`).
- **Risk:** None known. SHA-256 is a standard choice. This is only a difference from the paper. Whether the `cryptography` package exposes BLAKE2s is unverified: it is not installed in this environment, so I could not check. Check before any move to BLAKE2s.
- **Smallest change:** None needed. Interop with real WireGuard is not a goal.
- **Scope:** Out of scope. Reason: no interop goal, and no security benefit from changing the hash.

### G12. 32-bit sequence number instead of 64-bit counter

- **WireGuard:** 8-byte counter, rekey well before 2^64 (paper L768-770, L855-856).
- **Prototype:** 4-byte seq in the ESP header (`vpn_core.py:41`, `:50`). Rekey margin 1024 before 2^32 (`vpn_core.py:51`).
- **Risk:** About 2^32 packets per SA. With the time rekey in G2, this is not reachable in practice.
- **Smallest change:** Either ESN (64-bit extended sequence numbers, which `README.md:47` lists as not done), or rely on G2.
- **Scope:** Out of scope if G2 is done. Reason: ESN is more complexity for little gain in a prototype.

### G13. Ephemeral and intermediate secrets are not zeroed

- **WireGuard:** Ephemeral keys and intermediate values are zeroed after use (paper section VII-D L1120-1126).
- **Prototype:** Python `bytes` and `X25519PrivateKey` objects are not zeroed. Objects such as `IKEInitiator` keep `priv`, `ms`, `k_i2r` and so on until garbage collection.
- **Risk:** Low. Python cannot give a reliable zeroing guarantee.
- **Smallest change:** Drop references (`del`) after `finish()` or `handle_auth_i()`. This is weak and should not be presented as zeroing.
- **Scope:** Out of scope. Reason: language and runtime limit. Document it as a known limit rather than adding partial code.

### Low-priority findings (not in the top gaps)

- **L-a. SPI collision in `by_spi`.** `_new_spi()` is random (`vpn_core.py:356-357`). `by_spi` is one flat dict for all peers (`vpn_server.py:37`, `:66`). Two peers with the same inbound SPI would overwrite each other. Risk is small with few peers. Fix: check for collision before inserting. Scope: in scope, small.
- **L-b. README is out of date.** `README.md:46` says "no DoS limits on pending handshakes", but `MAX_PENDING` and eviction exist (`vpn_core.py:49`, `vpn_server.py:21-30`). Update the README after G1.
- **L-c. Padding.** ESP-style padding to 4 bytes (`vpn_core.py:140-143`). The paper zero-pads to 16-byte multiples to hide lengths (paper L774, L781-785). The prototype's trailer is the RFC 4303 form, which is a defensible choice. Do not switch to zero-padding just to copy the paper. If length hiding matters, pad to a larger bucket and keep the ESP trailer.
- **L-d. IPv4 only.** `esp_decapsulate` requires next header 4 (`vpn_core.py:175`). The paper supports IPv4 and IPv6 (paper L142-143). Out of scope unless IPv6 is needed.
- **L-e. Test gaps.** No tests for: time-based rekey (none exists), roaming, keepalive, cookie, cryptokey source check, handshake retry, SA replacement while packets are in flight.

---

## 3. Things to deliberately not copy

1. **Noise framework generality.** The paper uses a Noise-IK variant with a hash chain (paper L652-657, L691-707). The prototype's fixed four-message IKE-style exchange is easier to read. Do not import a Noise library or add pattern machinery. If G7 and G9 are ever done, adopt the paper's specific IK pattern, not the general framework.
2. **Cryptokey routing as a single table.** The paper's single table (section II) needs per-peer identities (G7). Doing it now without identities gives a table with one row. Do G3 first, as a simple allowed-source check.
3. **Kernel-only features.** The following do not apply to a Python user-space prototype: RCU radix tries (paper section VII-D L1087-1094), padata parallelism (VII-B), softirq (VII-B), RTNL and netlink (VII-C), GSO/GRO super-packets (VII-A), SipHash-keyed peer tables (VII-D L1095-1101), netfilter hashlimit (VII-D L1127-1132), `memzero_explicit` (VII-D L1120-1126), network-namespace isolation (VII-C L1068-1077, VII-E), FIB exclusion routes (VII-E).
4. **Cookie with rotating secrets, as a first step.** Implement mac1 (G1 step 2) first. The full mac2 cookie (G1 step 3) is more machinery than the threat model needs right now.
5. **Zero-padding to 16 bytes.** See L-c. Keep the ESP trailer.
6. **Exponential backoff in retries.** The paper calls it future work (L922-924). Use the paper's fixed 5 s interval, capped at 90 s (G4).
7. **BLAKE2s and "WireGuard v0" identifier string.** Interop is not a goal (G11). The prototype's labelled HKDF info strings already give domain separation.
8. **A 1-RTT handshake rewrite.** It is tempting, but it changes the security argument. See G9.

---

## 4. Recommended order of changes for a follow-up agent

Sizes: small (under about 50 lines plus tests), medium (about 50-150 lines or a wire-format change with tests), large (protocol redesign).

1. **Quick win: length check before `IKEResponder` construction** (`vpn_server.py:50-51`). Stops CPU work on malformed INITs. No wire change. Size: small.
2. **mac1 on INIT** (G1 step 2). Verify before DH. Store `pending` only after mac1 is valid. Update INIT builders and the eviction test in `test_vpn.py`. Size: medium.
3. **Inbound allowed-source check** (G3). After decryption, reject inner sources outside the peer's allowed list. Size: small.
4. **Time-based rekey and old-SA grace** (G2 steps 1 and 3). Add `created` to `SA`, raise `RekeyRequired` at 120 s, keep the previous inbound SPI for about 5 s. Size: small to medium.
5. **Handshake retry with 5 s interval and 90 s cap** (G4). Catch `socket.timeout`, use fresh ephemerals on each attempt. Size: small.
6. **Roaming** (G5). Update `sa.peer` only after successful decryption. Test that forged packets cannot move the endpoint. Size: small. Do this when a real-network test is planned.
7. **Keepalive** (G6). Zero-length plaintext treated as keepalive. Update `test_authenticated_empty_inner_does_not_crash_server`. Size: small. Deferred to real-network work.
8. **SPI collision check** (L-a) and **README update** (L-b). Size: small.
9. **Cookie mac2 reply** (G1 step 3, G10). Size: medium. Optional.
10. **Per-peer identity and static keys** (G7). Size: large. Needed before any multi-peer use. Also unlocks G8.
11. **Handshake replay timestamp** (G8). Size: medium. Depends on step 10.
12. **1-RTT handshake** (G9). Size: large. Out of scope for now.

---

## 5. Paper vs. current design: conflicts to note

- **1-RTT vs 2-RTT** (paper L129, L392-402 vs `vpn_client.py:47-51`).
- **Silence vs. reply to any well-formed INIT** (paper section V-A L411-424 vs `vpn_server.py:52-54`).
- **Endpoint roaming vs. pinned endpoint** (paper II-A L219-225 vs `vpn_core.py:160-161`).
- **Time-based rekey vs. count-only** (paper VI-B L869-874 vs `vpn_core.py:136-137`).
- **Per-peer static identity vs. shared PSK** (paper section V-D2 L703 vs `vpn_core.py:298-308`).
- **Keepalive for NAT:** the user brief says keepalives are used for NAT. The paper's NAT answer is roaming (L250-256). Persistent keepalive is optional (L253-256). The passive keepalive in section VI-E is for dead-peer detection, not NAT. Treat this as a nuance rather than a conflict.
- **"Avoids downgrade attacks":** the brief says the fixed suite avoids downgrade. The extracted paper does not use the word "downgrade". It justifies no agility by the cost of updating endpoints (L122-125). Both points are true of the prototype, but the paper's reason is different.

---

## 6. Test coverage relevant to the gaps

Existing tests that cover the design: `test_vpn.py` handshake, ESP round trip, tamper, replay, window, SPI, padding, sequence limit, size bounds, endpoint mismatch (which G5 would change), SPD, checksum, transcript binding, reflection, low-order points, bounded pending, oversized datagrams, client deadline, stale ESP during handshake.

Tests that G1-G6 changes will break or need rewriting:
- `test_pending_handshakes_are_bounded` (`test_vpn.py:320-337`): asserts eviction.
- `test_authenticated_empty_inner_does_not_crash_server` (`test_vpn.py:288-308`): asserts the zero-length drop.
- `test_endpoint_mismatch_rejected` (`test_vpn.py:153-158`): changes under G5.
- `test_low_order_peer_public_key_rejected_by_responder` and `test_server_survives_malformed_init_then_auth` (`test_vpn.py:222-225`, `:310-318`): INIT format changes under G1 step 2.
