# RFC 7296 (IKEv2) mapping for the handshake and rekey code

Partial review. Sections read are listed below with their status. Sections not read are at the end.
Source: https://www.rfc-editor.org/rfc/rfc7296.txt (sections 2.1, 2.4, 2.8, 2.8.1 and 2.8.2 read in
the RFC text; the others are listed as unread).

Note on section numbers: the retransmission brief cited 2.1 for both rules. In the RFC text, 2.1
("Use of Retransmission Timers") holds the bitwise-identical rule, and 2.4 ("State Synchronization and
Connection Timeouts") holds the exponential-growth rule.

| RFC section | What the RFC asks | What the tunnel does | Status | Test |
|---|---|---|---|---|
| 2.1 Retransmission | A retransmitted request MUST be bitwise identical to the original | Each retry builds a new INIT with a new ephemeral key, timestamp and sender index. A responder that already accepted the first INIT rejects the retry as a replay, so a lost RESP is only recovered by the next attempt | **Open** (deviation). Fixing it needs the responder to answer a duplicate INIT with its stored RESP | none |
| 2.4 Retransmission timing | Retransmission times MUST increase exponentially, to avoid flooding | Gaps are 5 s, 10 s, 20 s, then 20 s (cap), each +/-20 % jitter. The attempt is dropped at 90 s | **Fixed** | `test_gaps_double_then_cap_and_attempt_is_bounded`, `test_jitter_is_applied_to_every_gap`, `test_random_jitter_stays_inside_the_band` |
| 2.4 (first attempt) | Not stated; kept as before | The first INIT is sent at once, with no delay or jitter | Unchanged | `test_first_attempt_is_unchanged` |
| 2.8 Rekeying lifetimes | Each end enforces its own lifetime policy; lifetimes are not negotiated | Time limit (120 s) and message limit (2^32 - 1024) are local constants. Either side starts a rekey | Implemented | `test_rekey_by_time`, `test_rekey_by_message_count`, `test_responder_can_initiate_rekey` |
| 2.8.1 Simultaneous Child SA rekeying | Rekey requests SHOULD be jittered. The SA created with the lowest of the four nonces SHOULD be closed by its creator. Until resolved, accept packets on either SA | A due rekey waits a random 0 to 5 s. When two INITs cross, the one with the lower ephemeral public key wins. The winner ignores the other INIT. The loser drops its attempt and answers. Both sides see both keys, so no extra round trip is needed. Packets are still accepted on the previous session during the overlap. The tunnel compares ephemeral keys, not the RFC's nonces, which is a deliberate simplification | **Implemented** for jitter and the deterministic winner. The pre-rekey session is kept as `previous` on both sides, as in any rekey, and is replaced at the next rekey or expiry | `test_due_rekey_waits_for_its_random_delay`, `test_exactly_one_attempt_is_answered`, `test_both_sides_can_send_and_receive_after_the_collision`, `test_loser_leaves_no_session_from_its_own_attempt` |
| 2.8.2 Simultaneous IKE SA rekeying | The new IKE SA with the lowest nonce SHOULD be deleted by its creator. No jitter is stated | The tunnel has one SA type, so the 2.8.1 rule covers it. No separate IKE SA exists | Covered by the 2.8.1 mechanism; no separate test | as 2.8.1 |

## Not read (review is partial)

- 2.2, 2.3 (message IDs and windowing): not read. The tunnel has no message IDs, and it uses one
  outstanding INIT per peer.
- 2.4 INITIAL_CONTACT detail: not read beyond the retransmission rule above.
- 2.5 to 2.7 (version numbers, SPIs and cookies, algorithm negotiation): not read. Cookies are
  covered separately by `CookieTests`, not by this mapping.
- 2.8.3 (rekey versus reauthentication): not read.
- 2.9 (traffic selectors): not read. The tunnel uses its own SPD.
- 2.23 (NAT traversal): not read.
- Section 5 (Security Considerations): not read.
