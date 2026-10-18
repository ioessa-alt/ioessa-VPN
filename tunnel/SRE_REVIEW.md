# SRE review: ioessa tunnel prototype against *Building Secure and Reliable Systems*

Chapters reviewed: ch02, ch05, ch06, ch08, ch09, ch10 (main), ch11, ch12, ch13, ch15.
Book refs `L<n>` are line numbers in the converted `sre.txt`. Code is in `tunnel\`; tests are in `test_vpn.py` unless named.

## 0. Summary

**DoS (ch10) result.** Both suspected gaps were real, and the review found a worse one.

1. Unknown-index datagrams printed one line each with no limit. **Fixed**: a shared log budget
   (`Node._refuse`, `LOG_BURST = 20`, `LOG_RATE = 5` per second) limits printed refusals. Every
   refusal is still counted, and the shutdown line reports the count of refusals not printed.
2. No per-source rate limit. **Not built.** The budget is global, so it bounds output but does not
   protect one source from another. Per-source limits need bounded memory and a design choice.
3. **New, serious, fixed.** On Windows, after the server sends a reply to a client port that has
   closed, the next `recvfrom` raises `ConnectionResetError` (WSAECONNRESET). Neither `serve()` nor
   `serve_tun()` caught it, so the server process exited. The client already handled this in
   `vpn_client._recv_from`. Reproduced end to end on this host: with the handler removed, one valid
   INIT from a client that closes its socket at once made `vpn_server.py` exit with code 1. With the
   fix, the server keeps running. A client that quits during a handshake triggers the same thing.

**Other findings.** Restart cleared replay state, and a replayed INIT was then accepted. The reply
went to the replayer, and the server's endpoint for the peer moved to the replayer until the real
client sent again. CRYPTO_REVIEW F9 says the attacker "gets nothing", which is true for keys but
leaves out this side effect. **Fixed (restart item, section 6):** with `--state-file`, the
per-peer timestamp is persisted before the RESP is sent and reloaded at start. Test:
`test_replayed_initiation_rejected_after_restart`. Without the flag the server warns at start, and
the gap remains. Recovery after a server restart (without the flag) takes up to 120 s, and only if
the client is sending. The first-handshake retry had a fixed 5 s interval with no backoff or jitter;
that is now fixed (item 5 below). Several
existing docs are stale (section 9).

**Changes made (tunnel\ only, no wire-format change, no new dependencies):**

| File | Change |
|---|---|
| `vpn_core.py` | Shared log budget `Node._refuse` (`LOG_BURST`, `LOG_RATE`) for inbound refusals; unknown-key and stale-timestamp log reasons (wire unchanged) |
| `vpn_server.py` | `serve()` and `serve_tun()` ignore `ConnectionResetError` from `recvfrom`; shutdown count includes unprinted refusals |
| `test_vpn.py` | `FakeSock` raises queued exceptions; 4 new tests (`OperationsOutputTests` 2, `ResetTests` 2); `test_replayed_initiation_rejected` checks the new reason |

**Test results (run from tunnel\):**

```
python -m unittest
Ran 143 tests in 8.836s
OK
```

(138 at session start. Four tests are from this review. One more appeared in `test_vpn.py` during the session.) `python -m unittest discover -s analysis`: `Ran 28 tests`, `OK`.

**Mutation checks (scratch copies):** throttle forced open: `test_refusal_log_is_rate_limited...`
`FAILED (failures=1)`. Reset handlers removed: `ResetTests` `FAILED (errors=2)`.

## 1. Adversaries (ch02)

Adversary types the book names (L14-L30 motivations; L34-L94 profiles): hobbyists, vulnerability
researchers and red teams, governments (intelligence, military, policing), hacktivists, criminal
actors, insiders (first party, third party, related). Reliability adversaries include success
disasters (L11), routine hardware failures, and configuration changes.

| Adversary | Addressed? | Where | Test |
|---|---|---|---|
| Network attacker who alters or injects datagrams | Yes: data and handshake are authenticated | `open_data`, `consume_initiation`, mac1 | `test_tampered_ciphertext_rejected`, `test_bad_transcript_mac_rejected` |
| Passive eavesdropper (espionage) | Content yes. Metadata no: sizes, timing, indices in clear (U-I1) | `seal_data` | `test_identity_hidden_on_wire` |
| Replay attacker | Yes, while the responder's state survives. Restart resets INIT timestamps unless `--state-file` is set (section 6) | `ReplayWindow`, `Peer.last_init_ts`, `TimestampStore` | `test_replayed_initiation_rejected`, `test_replayed_packet_rejected`, `test_replayed_initiation_rejected_after_restart` |
| Flooder (fun, destruction, extortion) | Partly. Cheap rejection and cookies; no per-source limit or bandwidth cap (U-D5) | `Node.handle`, `_on_init` | `test_unauthenticated_floods_keep_no_state` |
| On-path relay | No (H-X12) | none | documented |
| Holder of a leaked client key | Partly. Remove from peer file and restart. No runtime revocation | `Node.remove_peer` (not called in production) | `test_removed_peer_session_is_dropped` (library only) |
| Holder of a leaked server key | No without a PSK (H-X11). With one PSK, partly (K-X1) | `_init_chain`, `_mac1_key` | `test_leaked_server_x25519_key_alone_cannot_read_an_initiation` |
| Local user or malware on the host; disgruntled first-party insider | No. Keys readable by same-user processes (K-I2). No audit trail (P-R1) | none | none |
| Accidental misconfiguration (reliability adversary) | Partly. TUN drops packets with no session (fail closed). Client BYPASS is the default outside `--protect` (fail open, D-I2). Peer file not integrity-checked | `serve_tun`, `Peer.route` | `test_server_drops_packets_with_no_matching_peer` (test_tun.py) |

## 2. Least privilege (ch05)

Book: security cannot rest on the assumption that nothing goes wrong (L230); a narrow administrative
API so each caller gets only what it needs (L288); access granted only for a limited time leaves less
standing privilege lying around (L497-L499); run as an unprivileged
user with sudo, capabilities, or SELinux (footnote 11, L545).

| Claim or practice | Code location | Status | Test |
|---|---|---|---|
| Root (or CAP_NET_ADMIN) is needed only to open `/dev/net/tun` and configure it | `tun_linux.py` L184-L191 (open, TUNSETIFF), `_run_ip` L159-L169 | Implemented as described | `test_off_linux_the_error_is_clear`, `test_configure_runs_commands_in_order`. Permission path not tested (needs root) |
| Process drops root after the TUN is configured | none. The server and client keep root for their whole run | **Gap** (not changed: privilege model is out of scope) | none |
| `ip` is found with `shutil.which` on PATH and then run as root | `tun_linux.py` L161 | **Gap**: use an absolute path such as `/sbin/ip`, or check ownership first | `test_run_ip_uses_argument_list_without_shell` (checks no shell, not the path) |
| Server binds loopback by default | `vpn_server.py` `--bind` default `127.0.0.1` | Implemented | none |
| Peer keys are taken from a file or env var, never source | `load_peer_publics` (`vpn_core.py` L316), `load_static_private` (L302) | Implemented | `test_static_keys_are_not_in_source` |
| Key files are checked for permissions on read | none. `vpn_keygen.py` L25 writes 0600 with O_EXCL. Windows ignores mode | **Gap** (K-I3) | none |
| Per-peer `allowed_ips` restricts what a peer may send | `Node._source_allowed`. Set only for `--tun linux` (`vpn_server.py` `main`, L207). Queue mode is permissive | Partly (D-S1) | none |

**What an operator must trust:** the server private key (anyone who reads it can impersonate the
server to every client that holds its public key); the peer public-key list (read once at start);
the optional PSK (one secret for all peers); root for the whole process in TUN mode; `ip` found on
PATH; the `cryptography` package and Python runtime; the OS network stack; and the host firewall,
which is not in the code (OPERATIONS_REVIEW sections 4 and 5).

## 3. Understandability (ch06)

Book: complexity that nobody manages is what most often makes a system hard to understand (L599). Compose a system
from small components so properties of the whole follow from the parts (L620). Boundaries and
interfaces need as much attention as the components (L634). Free-form payloads are hard to reason
about (L651).

| Claim or practice | Code location | Status | Test |
|---|---|---|---|
| Fixed-layout messages, size and type checked before parsing | `Node.handle` (`vpn_core.py` L815), `_check_shape` | Implemented | `test_oversized_datagrams_dropped_before_parsing`, `test_size_bounds` |
| Each property has a stated invariant (e.g. no state before authentication) | `Node` docstrings; THREAT_MODEL section 2 | Implemented | `test_unauthenticated_floods_keep_no_state` |
| One generic reason for every crypto failure, so the wire gives no oracle | `HS_FAIL` (`vpn_core.py` L86) | Implemented | `test_replayed_response_after_tunnel_up_changes_nothing`, `test_tampered_auth_message_rejected` |
| Small modules | `vpn_core.py` is 835 lines and holds the protocol, config loading, TUN interface and helpers | **Gap** (not split: out of scope) | n/a |
| Two event loops with different timer rules | `serve()` (L53) runs `node.poll` only on a socket timeout. `serve_tun()` (L116) runs it every loop | **Fixed in the second pass**: `serve()` now runs `node.poll` once per tick even under steady traffic, and `serve_tun()` runs it on the same fixed schedule. Was: under steady traffic the default queue-mode server never ran timers (session expiry, keepalive) | `TimersUnderLoadTests` (test_hardening.py) |

## 4. Resilience (ch08)

Book: resilience objective of load shedding is to keep a component stable at maximum load, serving
errors rather than crashing (L962). Priorities should decide what is shed (L963). Security-critical
operations should not fail open (L984). Self-contained degradation, so external signals cannot force
an outage (L974).

| Claim or practice | Code location | Status | Test |
|---|---|---|---|
| Under load, an INIT without a valid mac2 gets a cookie reply and no DH work | `Node._on_init`, `_under_load` (L687) | Implemented. The count is global, not per source | `test_mac2_checked_under_load` |
| Refusals do not crash the server (ch08: answer with an error instead of crashing) | `serve`, `serve_tun` | **Was broken on Windows** (ICMP reset). **Fixed in this review** | `ResetTests.test_serve_survives_reset_and_handles_next_datagram`, `ResetTests.test_serve_tun_survives_reset` |
| Malformed input does not raise out of `Node.handle` | `Node.handle`, mutation fuzz | Implemented for the inputs tried | `test_server_survives_malformed_init_then_auth`, `test_mutated_handshake_messages_never_raise_or_establish_a_session`, `test_mutated_data_packets_are_never_delivered` |
| Request priority (shed low-priority work first) | none. All INITs are equal. The data path has no load check | **Gap** (not needed for this two-party tunnel) | none |
| Client retry: exponential backoff with jitter (book L1538) | `Node._retry_interval`, `Node._send_init`, `Node.poll`. Gaps are 5 s, 10 s, 20 s (cap 20 s), each +/-20 % jitter; attempt dropped at 90 s | **Fixed.** Still open: a retry is a new INIT, not bitwise identical (RFC 7296 2.4, see RFC7296_REVIEW.md) | `test_gaps_double_then_cap_and_attempt_is_bounded`, `test_jitter_is_applied_to_every_gap`, `test_random_jitter_stays_inside_the_band`, `test_first_attempt_is_unchanged` |
| Fail closed when there is no session (no clear fallback on the server) | `serve_tun` drops with "no peer with a session" | Implemented on the server. Client BYPASS fails open by design (D-I2) | `test_server_drops_packets_with_no_matching_peer` |
| Bounded output under attack | `Node._refuse` (`vpn_core.py` L692) | Implemented in this review (section 5) | `test_refusal_log_is_rate_limited_but_still_counted` |

## 5. DoS (ch10), main chapter

Book: layer defenses so each layer protects the next, with shared infrastructure outside the
service. Throttle top sources (L1501) and expect collateral damage from IP-based blocks (L1507). The DoS defense must be resilient to attack itself (L1516). Fail static, neither closed
nor open, when the controller fails (L1518). A clever adversary may simulate legitimate traffic, so
throttles may not be sufficient (L1494).

| Claim or practice | Code location | Status | Test |
|---|---|---|---|
| Cheap rejection before expensive work: size, shape, then mac1 (keyed BLAKE2s), then DH | `Node.handle` (L815), `_on_init` | Implemented | `test_mac1_checked_silently`, `test_oversized_datagrams_dropped_before_parsing` |
| Data path: session index lookup before AEAD | `_on_data` (L907), `open_data` (L514) | Implemented | `test_flood_of_unknown_index_datagrams_is_counted` |
| Cookie: MAC over source IP, rotating secret, cookie reply encrypted and bound to the INIT | `make_cookie_reply`, `consume_cookie`, `_cookie_secrets` | Implemented (IP only, C-X1) | `test_cookie_is_bound_to_source_address`, `test_cookie_secret_rotates`, `test_cookie_reply_bound_to_initiation` |
| Bounded state: nothing kept for unauthenticated input except the INIT times of the last second | `Node` fields; `_hs_times` (L844) | Implemented | `test_unauthenticated_floods_keep_no_state` |
| DH work capped per second | `_under_load`, `load_threshold` (default 50). Cookie replies do not count, so DH resumes after the window empties. By reading the code, not measured | Partly (global) | none measured |
| Replies smaller than requests (no amplification) | cookie 72 B, RESP 1180 B, INIT 1236 B (sizes after the ML-KEM step, CRYPTO_REVIEW F10) | Implemented (U-D4) | `test_responses_are_smaller_than_the_initiation`, `test_authenticated_data_gets_no_reply` |
| Mac1 is keyed from the server's public key, which is public. Mac1 filters noise, not attackers. The DH cost of a valid-mac1 flood is what the cookie limits | `_mac1_key`, `make_initiation` | Known. Documented in THREAT_MODEL P-D3 | `test_unauthenticated_floods_keep_no_state` (forged INITs with valid mac1) |
| Per-source rate limit | Built for INIT handshake work: token bucket per source address (`SRC_INIT_RATE` 2/s, burst 20, table bounded). Spoofed sources bypass it | `Node._source_budget`; `test_flood_from_one_source_is_refused_after_the_burst` |
| Log throttle for refused input (shared, bounded) | `LOG_BURST = 20`, `LOG_RATE = 5`, `Node._refuse` (L692) | **Implemented in this review**. Global, not per source | `test_refusal_log_is_rate_limited_but_still_counted` |
| Cookie replies and "under load" lines are not throttled | `_on_init`, under-load branch | **Gap**: volume cost of about 0.49x the request, per valid-mac1 INIT. Printed line is not rate-limited | none |
| Server survives a reset from an earlier reply (Windows) | `serve`, `serve_tun` | **Fixed in this review**. Before the fix: one INIT and a closed client port killed the process (end-to-end run, section 10) | `ResetTests` (2 tests); mutation check gave `errors=2` |
| Client survives a reset and keeps its deadline | `vpn_client._recv_from` (L32-L50) | Implemented | `test_recv_survives_icmp_reset_and_returns_server_datagram`, `test_recv_times_out_when_only_resets_arrive` (test_fixes.py) |
| Client receive has an overall deadline | `vpn_client._recv_from` | Implemented | `test_receive_has_overall_deadline` |
| Upstream filtering, ACLs, edge throttling | none in code | Accept. OPERATIONS_REVIEW sections 4 and 5 | n/a |

## 6. Design for recovery (ch09)

Book: recovery starts with a known good state, defined exactly, byte for byte (L1349). Emergency
push = regular push turned up (L1231). What matters is being able to restore, not having backups
(L1371). Test recovery itself (L1378, L1380).

| Claim or practice | Code location | Status | Test |
|---|---|---|---|
| No persistent session state: a restart starts clean, and new sessions use new ephemerals and keys | `Node` (in memory only) | Implemented. CRYPTO_REVIEW "crash recovery" claim is correct | none; checked in `restart_check.py` (scratch) |
| After a server restart, the client's session is dead. Recovery waits for the client's time-based rekey (120 s), and only if the client has sent data | `Node._rekey_due`, `Node.poll` | **Verified** (step 3-4 of restart_check). Slow, undocumented in the reviews | none |
| Restart clears INIT timestamps, so a captured INIT is accepted again. The response goes to the replayer's address | `Node._on_init`, `Peer.last_init_ts`, `TimestampStore` | **Fixed** with `--state-file` / `IOESSA_VPN_STATE_FILE`. Timestamp is written before the RESP; malformed file stops startup; without the flag, startup warns. Tests: `RestartTests.test_replayed_initiation_rejected_after_restart`, `test_state_file_holds_timestamp_before_resp_is_built`, `StartupTests`; end-to-end run (real server process, restart, replay) rejected. Not covered: state-file rollback or deletion, and two processes on one file | `test_state.py` (14 tests) |
| The replayed INIT moves the peer endpoint to the replayer until a real packet arrives. The reviews say the attacker "gets nothing" (CRYPTO_REVIEW F9) | `_on_init` (`_set_endpoint`, L860) | **Verified. Not in the reviews.** The attacker gets only handshake replies. Traffic from the server in that window goes to the attacker's address. Not changed: WireGuard does the same. **Stale, fixed later:** an INIT no longer moves the endpoint (`test_replayed_init_after_restart_does_not_move_endpoint`, test_hardening.py) | none |
| First handshake lost: the client retransmits at about 5 s, 10 s, 20 s (+/-20 %) up to `--timeout`, then exits. The node gives up its pending INIT after 90 s and does not restart with no session | `vpn_client.handshake` (L59), `Node.poll` | **Verified** (restart_check 5a, 5b) | none |
| Intended state of the peer list is checked against nothing: no hash, read once at start, log shows only a count | `load_peer_publics` (L316); `vpn_server.py` main prints `(N peer(s))` | **Gap** | none |
| Fast revocation: `remove_peer` exists but no runtime reload path. Revocation is a restart | `Node.remove_peer` (L662) | **Gap** (KEY_LIFECYCLE section 2) | `test_removed_peer_session_is_dropped` (library only) |
| Recovery is tested: restart, rekey after restart, rebuild from empty peer list | none | **Gap** | none |

## 7. CA case study (ch11)

Book: the root key is kept offline, behind two-party authorization. Day-to-day issuance uses online
intermediates (L1619). Rotating keys after a compromise is slow, so the CA "matures other root key
material ... so we can swap in alternate material" (L1619). Limited functionality is easier to audit
(L1603). Parse untrusted input in one zone and check it in another (L1594). Centralize ACL checks so
new RPCs cannot skip them (L1604).

- *Alternate key material.* The peer file takes several client keys, so a client key can overlap
  during rotation (KEY_LIFECYCLE 3.1). A server key cannot: there is one private key and no
  pre-distributed second key. The book's lesson (L1619) is not met. Not built (a rotation design change).
- *Limited functionality (L1603).* One suite, fixed message types (H-X5).
- *Centralized checks.* `Peer.route` is the single routing decision. `allowed_ips` is not enforced in queue mode.
- *Not applicable:* certificate issuance, CT logs, HSMs, audits. The tunnel has no CA.

## 8. Writing and testing code (ch12, ch13)

Book: frameworks should enforce invariants so each application does not have to (L1653). Automatic
redirection away from overloaded instances (L1659). Hermetic tests (L2007). Security tests for
malformed input and negative values (L2008). Mutation testing shows whether tests catch changes
(L2012). Fuzzing finds crashes, and inputs that hang can cause DoS (L2086, L2100). Do not mirror
sensitive production data into tests (L2032).

| Claim or practice | Code location | Status | Test |
|---|---|---|---|
| Invariants held in one place: `_refuse` for inbound refusals; `_check_shape` for fixed fields | `vpn_core.py` | Implemented in this review for refusals | `test_refusal_log_is_rate_limited_but_still_counted` |
| Security-focused negative tests (malformed, forged, replayed, reflected) | `test_vpn.py` (most of the 143 tests) | Implemented | e.g. `test_reflected_handshake_messages_rejected`, `test_forged_or_replayed_packet_does_not_roam` |
| Every security claim in THREAT_MODEL names a test that exists | THREAT_MODEL section 2 | Checked: all 48 test names listed there exist as `def test_...` in the test files. Name check only, not a check that each test proves its claim | n/a |
| Mutation testing | `test_mutated_*` (random byte and bit mutation, seed fixed) and the mutants in this review | Partial: random mutation, not coverage-guided. Three mutants run in this review (section 0) | `MutationFuzzTests` |
| Fuzzing with a coverage-guided engine | none | **Gap** | none |
| Hermetic tests: loopback only, no real network | `test_tun.py` `TunLoopTests` | Implemented | `test_host_packet_crosses_the_tunnel_both_ways` |
| Static analysis and sanitizers in the pipeline | none. Python only. Not run for this review | Not done | none |

## 9. Investigation and logs (ch15)

Book: debugging is code-focused; a security investigation is about the actor (L2582). A debugger that
deletes files can alert an attacker (L2583). Logs that are missing, truncated, or corrupted are a
sign of tampering (L2587). Store logs immutably and remotely, so an attacker must compromise the log
server too (L2597-L2598). Plan depth, retention, and privacy (L2604, L2606, L2610, L2612).

| Claim or practice | Code location | Status | Test |
|---|---|---|---|
| A rejected handshake shows the source address and a reason | `_on_init` (L848-L857). Reasons: unknown peer key; stale or replayed timestamp; generic for crypto failures | **Changed in this review** (two specific reasons, local only) | `test_handshake_refusal_log_gives_reason_without_key`, `test_replayed_initiation_rejected` (updated) |
| Crypto failures (bad AEAD, bad transcript) are still generic | `HS_FAIL` at `vpn_core.py` L86 | Gap for investigation (a bad transcript and a wrong responder key look the same). Kept generic to avoid over-detail | `test_bad_transcript_mac_rejected` |
| No key material in any log line | `_refuse` messages are fixed strings plus the address; key loaders name the setting, not the value | Implemented | `test_bad_key_error_does_not_echo_value`, `test_handshake_refusal_log_gives_reason_without_key`, `test_payload_printed_only_with_show_payload` |
| Logs carry a time | none. stdout only, no timestamps (OPERATIONS_REVIEW 3.1) | **Gap** | none |
| Logs are immutable and remote | none. stdout only. A flood of refusals fills the log (throttled now, section 5) | **Gap** (book L2597-L2598) | none |
| Shutdown counter reflects refusals that were not printed | `vpn_server.py` main: `counter.count + node.refusals_unlogged` | **Implemented in this review** | `test_flood_of_unknown_index_datagrams_is_counted` (count path) |
| Investigator can separate a wrong peer key from an attack | "unknown peer key" in the log, separate from "stale or replayed timestamp" | **Implemented in this review** | `test_handshake_refusal_log_gives_reason_without_key` |

## 10. Verification (outputs from this review)

- `python -m unittest` (tunnel\): `Ran 143 tests in 8.836s` / `OK`.
- `python -m unittest discover -s analysis`: `Ran 28 tests in 2.082s` / `OK`.
- Restart fix (added later): `python -m unittest` (tunnel\) with `test_state.py`: `Ran 157 tests` / `OK`.
  End-to-end on the real `vpn_server.py` with `--state-file` in a temp directory: handshake, restart,
  replayed INIT got no RESP and the log shows `stale or replayed timestamp`; a newer INIT after the
  restart was answered. Temp directory removed afterwards.
Scratch scripts (not in the repo) are in `...\scratchpad\sre_checks\`.
- `udp_reset_check.py`: `recvfrom` raises `ConnectionResetError: [WinError 10054]` after a reply to a closed port.
- `e2e_reset.py`, real `vpn_server.py`, one real INIT. Reset handler removed, client closes at once:
  `server exited with code 1`, stderr `ConnectionResetError: [WinError 10054]`. Current code, client
  closes: `server still running`. Current code, client keeps its socket: `client received reply type 2`,
  `server still running`.
- `restart_check.py`, in-process, fake clock: replayed INIT after restart gets a response and moves the
  endpoint; legit packets are `unknown index` until the rekey at +120 s (0 packets at +119 s, 1 at +121 s);
  a lost first INIT is retried at about 5 s (+/-20 %), and nothing is sent at +200 s.
  **Stale, fixed later:** the replayed INIT no longer moves the endpoint (`test_replayed_init_after_restart_does_not_move_endpoint`, test_hardening.py:100).

## 11. Gaps left open

1. Per-source rate limit (U-D5). Needs bounded per-source state and a design choice.
2. Cookie replies and the "under load" line are not throttled.
3. Privilege drop after TUN setup; `ip` resolved on PATH as root (use an absolute path).
4. Key-file permission check on read (Windows ignores modes).
5. Client retry has no backoff or jitter. FIXED: gaps double to a 20 s cap with +/-20 % jitter, and the attempt ends at 90 s (`RetransmitBackoffTests`).
6. Runtime revocation and peer-file reload. Needs a Windows-friendly trigger; a design choice.
7. Server key rotation has no overlap (ch11 lesson).
8. **Stale, fixed later:** timers in the queue-mode server no longer run only when idle. `serve()` calls `poll()` once per tick under steady traffic (`vpn_server.py` lines 86-87; `TimersUnderLoadTests.test_poll_runs_during_steady_traffic`, test_hardening.py:158).
9. No time in logs; no remote or immutable log.
10. No coverage-guided fuzzing; no recovery test beyond the replay-after-restart case; no static analysis run.
11. Crypto-failure log reason is still generic.

## 12. Stale statements in other docs (corrected in place in the finalization pass)

Corrected: `OPERATIONS_REVIEW.md` 3.1, 9 and the test-count lines; `THREAT_MODEL.md` P-E1 and D-E1 were already
updated. `CRYPTO_REVIEW.md` F9 and `ZERO_TRUST_REVIEW.md` section D now note the endpoint fix.

- `OPERATIONS_REVIEW.md` 3.1 and 9: "unknown-index flood prints one line per datagram". Now bounded
  (globally). Unknown key and stale timestamp now print different reasons.
- `THREAT_MODEL.md` P-E1: "No admin rights". False for `--tun linux` (root, `tun_linux.py` L11, L184-L188).
- `THREAT_MODEL.md` D-E1: "Not implemented". Stale: `LinuxTun` exists (THREAT_MODEL section 6).
- `CRYPTO_REVIEW.md` F9, `ZERO_TRUST_REVIEW.md` section D: correct on keys and replay. Both omit the
  endpoint change after a replayed INIT (section 6).
