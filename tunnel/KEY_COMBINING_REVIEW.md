# Key combining review (Boyd and Mathuria, ch. 5 and §1.5)

Scope: how the final handshake (`vpn_core.py`, after the ML-KEM-768 change, CRYPTO_REVIEW F10)
combines its secrets into the chaining key `ck`. Reviewed against the book's key-control,
unknown key-share and freshness points. The chapter's other protocols (MTI, identity-based,
conference) are not covered here.

## The schedule

Every step is `ck, k = _kdf(ck, input)`, the HKDF-Extract shape over HMAC-BLAKE2s, with `ck`
as the key and the new material as the input.

| Step | Initiator (`make_initiation`) | Responder (`consume_initiation`, `make_response`) |
|---|---|---|
| Chain start | `ck`, `h` from the construction, the identifier, `S_r` and `K_r` (ML-KEM public key) | same |
| PSK (optional) | `_kdf(ck, E_i)` | same |
| Initiator ephemeral | `h = H(h, E_i)` | `h = H(h, E_i)` |
| ML-KEM to responder | `ss, ct = Encaps(K_r)`, `h = H(h, ct)`, `ck = KDF(ck, ss)` | `Decaps(ct) = ss`, same mix |
| DH(E_i, S_r) | `ck, k = KDF(ck, DH(E_i, S_r))` | `DH(S_r, E_i)`, same |
| DH(S_i, S_r) | `ck, k = KDF(ck, DH(S_i, S_r))` | same |
| Encrypted static `S_i` and timestamp | AEAD under `k` | AEAD under `k` |
| Responder ephemeral | `E_r` and `ct_r = Encaps(K_i)` (`make_response`) | fresh `E_r` and `ct_r` |
| DH(E_r, E_i), DH(E_r, S_i) | after `h = H(h, E_r)` and `H(h, ct_r)` | `DH(E_i, E_r)`, `DH(S_i, E_r)` |
| ML-KEM from responder | `KDF(ck, ss_r)` | `Decaps(ct_r) = ss_r`, same mix |
| Confirmation | responder's empty AEAD under `k` (checked by initiator) | |
| Transport | `k_i2r, k_r2i` from `ck` with direction labels | same |

The order of mixing is the same on both sides, and each secret enters once, in the same place
on both sides. I checked this against the code line by line. The test helper `pair()` in
`test_vpn.py` completes the handshake and exchanges data both ways, which fails unless both sides
derive the same keys.

## Checks against the book

**1. One-way combining (§1.5).** The book requires that once one party has fixed its input, the
other cannot choose its own input to force a chosen output. Each step here computes
`HMAC(ck, input)`, keyed by the running chaining key. A party that knows its own input cannot
invert HMAC to force a particular output, so this holds. Result: **meets the requirement.**

**2. Unknown key-share (§5.1.2).** The book's general defence is to bind both principal
identities into the key derivation function. Here `S_i` and `S_r` both enter `ck`. `S_r` enters
the chain through `DH(S_i, S_r)`, and `S_r` and `K_r` are hashed into `h` from the start.
`S_i` is encrypted under a key derived after `DH(E_i, S_r)` and is hashed into `h`. Any mismatch
of identities changes `ck` and fails the AEAD, which the existing test
`test_reflected_handshake_messages_rejected` (THREAT_MODEL H-X2) covers. Result: **defended.**

**3. Key confirmation (§5.1.2 and ch. 3).** The book asks that confirmation messages identify both
principals. The responder's confirmation (empty AEAD under a key that needs the responder's ephemeral private
key, or the initiator's ML-KEM private key, to compute) is checked by the initiator. The initiator's identity is inside `h` from the encrypted static key, so
the confirmation covers it. Result: **defended** (THREAT_MODEL H-X10 covers the derivation).

**4. Key control (§5.1.1). Finding K1, Low, accepted.** The initiator's inputs (`E_i`, `ss_i`) are
fixed in the INIT. The responder then chooses `E_r` and `ss_r` knowing them. This is exactly the
situation the book describes: the second party can bias some bits of the key. The book's remedy
is a commitment message before the first party reveals its input. The protocol does not do this,
and the book notes that most published protocols don't either.

Why it is Low here:
- The responder only biases bits of a key whose other input (`E_i`, fresh per handshake) the
  responder cannot choose. It cannot force a reused key, which is the attack the book warns about.
- A responder that is malicious is already in a position to attack the session. The key-control
  question only matters against a legitimate responder that makes a mistake, or a compromised one
  that is still bound by the other checks.

Remedy if it is ever needed: a hash commitment to `E_i` and `ss_i` in the INIT, opened later.
That costs bytes in a message that is already 1236 bytes (`INIT_LEN`), so it is not free. Not planned.

**5. Hybrid use of the ML-KEM secret.** `ss` is combined with `KDF(ck, ss)`, which is the
HKDF-Extract structure: the chaining key is the HMAC key and the shared secret is the input. This
is the setting where HMAC's dual-PRF property applies to a secret input, so the output stays secret
if either the DH or the KEM secret is still secret. This is consistent with the Noise hybrid
pattern. Not independently proven here.

## Not covered
- The book's security models and proofs for these protocols (ch. 2 §2.6). The review checks the
  combining shape, not a proof.
- Any change to the KDF labels or the order of mixing. Those change the protocol and need a new
  review and interop note.
