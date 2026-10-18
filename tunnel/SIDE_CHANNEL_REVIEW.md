# Side-channel review: timing and cache

Date: 2026-10-16. Scope: `tunnel\` production code (`vpn_core.py`, `vpn_server.py`, `vpn_client.py`, `vpn_keygen.py`). `tun_linux.py` has no secret comparisons and was not reviewed line by line. `tunnel\analysis\` was not edited.

Sources read:
- *Computer Organization and Architecture* (Stallings), Ch. 4 "Cache Memory", section 4.3 "Elements of Cache Design" (book p. 125, logical versus physical caches; cache coherence on a shared bus, page not checked). Ch. 8 "Operating System Support", section 8.1 (book p. 273, memory protection) and section 8.4 (book pp. 294-295, protection via paging and segments).
- Earlier reviews: `RANDOMNESS_REVIEW.md` and `CRYPTO_REVIEW.md`. Neither covers timing.

The book does not discuss timing attacks or cache side channels. Nothing below is attributed to it beyond what those sections say. The cache-attack reasoning comes from general knowledge of the threat model and is labelled as such.

## Summary

- Secret-dependent comparisons in our code: 3 sites. 2 were already `hmac.compare_digest` (`_check_mac1`, `_check_mac2`). 1 was a plain `==` (`_dh` all-zero check). That one is now `hmac.compare_digest`. Remaining plain comparisons on secret values: 0.
- Tag verification (AEAD) is done inside the `cryptography` package. It is not in this repo and was not inspected.
- Protocol-level branches that depend on secrets: none that leak a secret through control flow. The data-dependent branches that remain test public values (indices, lengths, counters, reserved bytes) or values the attacker cannot forge.
- Realistic exposure: a remote attacker can only time the network path, and per-packet Python overhead makes that very noisy. A cache attack needs a local co-resident observer. For a VPN endpoint that is a shared host or co-tenant VM, and the most likely target is library code (X25519, ChaCha20, BLAKE2s), not `tunnel\`.
- No timing was measured. No cache attack was attempted.

## 1. Inventory: secret or attacker-influenced comparisons and branches

Line numbers refer to `vpn_core.py` as of this review. "CT" = constant time (`hmac.compare_digest`). "Plain" = `==`, `!=`, `in`, `<=`, or an early return.

| # | Location | Check | Value kind | Comparison | Status |
|---|---|---|---|---|---|
| 1 | `_dh` (line 191) | shared secret == all zeros | DH output, secret | was plain `==` | **Changed to CT** |
| 2 | `_check_mac1` (line 245) | mac1 tag | attacker-supplied tag, key from public key and PSK | `hmac.compare_digest` | CT (already) |
| 3 | `_check_mac2` (line 253) | mac2 tag, per cookie secret | attacker-supplied tag, cookie secret | `hmac.compare_digest` in a loop over current and previous secret | CT compare. The loop exits early on a match, which reveals only whether the current or previous secret matched. Low concern |
| 4 | `_aead_open` (lines 174-178), via `consume_initiation` (399, 402), `consume_response` (440), `consume_cookie` (469) | AEAD tag, 4 call sites | attacker-supplied tag, handshake keys | inside `cryptography` (ChaCha20Poly1305.decrypt) | Delegated to library. Not inspected |
| 5 | `open_data` (lines 525-528) | AEAD tag, data packets | attacker-supplied tag, transport key | inside `cryptography` | Delegated to library. Not inspected |
| 6 | `_is_low_order` (lines 200-203) | low-order public key | configured public key, not secret | exception from library | Not secret |
| 7 | `public_key_from_b64` (line 295), `load_psk` (line 334) | key length, low-order check | configuration | plain `len` and exception | Not secret. The PSK value is never compared |
| 8 | `_check_shape` (line 261), `consume_initiation` (line 389), `consume_response` (428), `consume_cookie` (464) | message type, length, reserved bytes `msg[1:4] != bytes(3)` | public wire fields | plain `!=` | Not secret |
| 9 | `consume_response` (line 429), `consume_cookie` (line 465) | local sender index echoed in reply | public wire field | plain `!=` | Not secret |
| 10 | `handle` (line 786), `_on_init` (800), `_on_resp` (832), `_on_cookie` (855) | size bounds, reserved bytes | public wire fields | plain `!=` and `len` | Not secret |
| 11 | `open_data` (line 533) | padding bytes `1, 2, 3, ...` | decrypted plaintext | plain `!=` | Runs only after the AEAD tag has verified, so the attacker has no oracle. Not changed |
| 12 | `open_data` (lines 519, 531) | counter range, `next_hdr`, `pad_len` | public header, decrypted plaintext | plain `>` and `!=` | Not secret. Post-auth for the trailer |
| 13 | `ReplayWindow.check` (lines 121-129) | counter vs. top and bitmap | public counter | plain `==`, `>`, bit test | Not secret |
| 14 | `_on_init` (line 817) | `info.timestamp <= peer.last_init_ts` | decrypted TAI64N, authenticated | plain bytes `<=` | Replay ordering, not a secret. Not changed |
| 15 | `_on_init` (line 816) | `self.peers.get(info.peer_pub)` | static public key from decrypted INIT | dict lookup (hash, then equality on hit) | Identity-hiding means the peer key is not public until decryption, so this is technically a secret-dependent lookup. Hash-based lookup, not a byte-wise compare. Not changed |
| 16 | `_new_index`, `_on_resp`, `_on_data`, `_on_cookie` (lines 658, 834, 857, 870) | `idx in sessions` / `pending.get(...)` | local index, public on the wire | dict lookup | Not secret |
| 17 | `_cookie_secrets`, `_fresh_cookie`, `_under_load` (lines 662, 672, 667) | time comparisons | clock | plain `<`, `>=` | Not secret |
| 18 | `seal_data`, `_rekey_due` (lines 496, 712, 714) | counter and time limits | local counters | plain `>=`, `==` | Not secret |
| 19 | `_mac` (line 151), `_dh` return path, `make_initiation` (line 382), `make_response` (line 421) | `if key:`, `if cookie else` | presence of a value, not its content | truthiness | Not a value comparison |
| 20 | `_set_endpoint` (line 902), `_source_allowed` (line 899), `vpn_server.py` 84-85, `vpn_client.py` 45 | endpoint and allowed-IP matching | public addresses | plain `!=`, `in` | Not secret |

Counts:
- Constant-time checks on secret or attacker-tag values: 3 (rows 1, 2, 3). Before the change, 2 (rows 2, 3).
- Plain checks on secret values: 0 (1 before the change).
- Tag checks delegated to the `cryptography` library: 5 call sites (rows 4, 5). Not verified in this review.
- Plain checks on public, configuration, or post-auth values: rows 6-20. Not secret, so not changed.

## 2. Judgment: which cache and timing leaks matter here

Threat model from the cache chapter. Stallings 4.3 says that a logical (virtual) cache has to be emptied on every switch between applications, unless each cache line carries extra bits that say which virtual address space it belongs to Cache state is therefore shared across processes unless the OS and hardware separate it. Section 8.1 and 8.4 describe memory protection as access control over address spaces (monitor area, paging, segments). They do not describe micro-architectural state, which sits below that layer. Inference from this: a process can be isolated at the address-space level and still share cache lines with another process. That is what a cache side channel exploits. The book does not say this. It is the standard reasoning, and it is labelled as inference.

Applied to a VPN endpoint:

1. **Remote network attacker (the usual VPN adversary).** Can send packets and measure response times. Cannot read cache state. Only the timing of comparisons is relevant. Our two MAC compares were already constant-time. The DH zero check was not, and now is. Realistic risk from `tunnel\` code: low, because the attacker learns at most a few bits per handshake, and the per-packet Python overhead adds much more jitter than a single comparison.

2. **Local co-resident observer (another process or VM on the same host).** This is the case cache attacks need. It matters only if the endpoint runs on a shared host. The secrets in memory are the static private key (loaded from env or file), session transport keys, and the chaining state `ck` and `h`. Those secrets are touched by `cryptography`'s X25519 and ChaCha20 code, not by `tunnel\` code. The protocol code here does no table lookups indexed by secret data, so it does not add a cache-indexed leak of its own. Any real leak would be in the library implementations, which this review did not inspect.

3. **Python-level effects.** The interpreter, the garbage collector, and `bytes` copies are not constant-time and leave secrets in memory (already noted in `CRYPTO_REVIEW.md` F6). These are a memory-exposure issue, not a control-flow timing leak in this code.

4. **Branches on secrets in `tunnel\`.** None found that leak a secret through control flow. The `_check_mac2` early exit reveals only which of two random, rotating cookie secrets matched, not the secret. The shared-secret zero check was the one real case, and it is fixed.

Realistic exposure, stated plainly:
- Remote timing of tag comparisons: mitigated by constant-time compares (already in place for MACs; now for the DH check).
- Cache or other local side channels: applicable only to a co-tenant threat model. The exposure is the `cryptography` library and the Python runtime, not this repo's logic. Nothing in this repo mitigates it, and nothing here was measured.
- This review does not claim the tunnel resists local side channels.

## 3. Changes

Only one code change was needed.

- `vpn_core.py`, `_dh`, line 191. Before: `if shared == bytes(len(shared)):`. After: `if hmac.compare_digest(shared, bytes(len(shared))):`. Reason: the shared secret is a secret value, and a plain `==` stops at the first differing byte. The change is one line, uses an already-imported module, and does not change the wire format or results.

Not changed, with reasons:
- Row 11 (padding check after AEAD): runs only after authentication, so there is no oracle.
- Row 14 (timestamp order) and row 15 (peer lookup): not secret comparisons in the sense of the task, and the lookup is hash-based. A change here would be a behaviour change without a demonstrated gain.
- Row 3 (early exit in `_check_mac2`): reveals only which of two secrets matched. Fixing it would mean always checking both, a small change, but the leak is not of a secret.

## 4. Tests

New class `SideChannelCompareTests` in `test_vpn.py` (4 tests). They are functional checks, not timing tests:

- `test_dh_rejects_all_zero_output`: a stand-in key whose `exchange` returns 32 zero bytes must make `_dh` raise `HandshakeError`.
- `test_dh_accepts_nonzero_output`: a non-zero output must be returned unchanged, so the check is not always true.
- `test_mac1_rejects_wrong_tag`: a valid INIT's mac1 passes, and one flipped bit fails.
- `test_mac2_rejects_wrong_tag_and_wrong_address`: a valid mac2 for one address and secret passes, and a flipped bit or a different source address fails.

Timing tests were not written. Timing measurement in Python is not reliable: interpreter noise, GC pauses, and OS scheduling dominate a single comparison, and results would not support a claim either way.

## 5. Test results

```
python -m unittest
Ran 114 tests in 7.234s
OK
```

Baseline before the change: `Ran 110 tests in 7.206s`, `OK`. The 4 new tests account for the difference.

## 6. Unverified

- No timing was measured. Not in Python, not on Windows, not on Linux. No claim of constant-time behaviour is made beyond the use of `hmac.compare_digest` at the call sites listed.
- The AEAD tag comparisons (rows 4, 5) happen inside the `cryptography` package. Its constant-time behaviour was not inspected or tested.
- X25519 and ChaCha20 implementations in the `cryptography` backend were not inspected for cache-dependent table lookups or other secret-dependent memory access.
- `hashlib.blake2s` and `hmac` (C backends) were not inspected for timing behaviour.
- The cache chapter does not discuss timing or cache side channels. The threat-model reasoning in section 2 is general knowledge, not taken from the book.
- No co-resident attack, Flush+Reload, or Prime+Probe experiment was run.
- Windows behaviour of `hmac.compare_digest` (CPython) was not measured.
