# Formal model of the handshake (ProVerif)

Model: `ioessa_handshake.pvt`, a template that follows `vpn_handshake.py` step by step.
Runner: `run_proverif.py` fills the template for each attacker variant, runs each query alone
(`PROVERIF_JOBS`, default 1; `PROVERIF_TIMEOUT`, default 1800 s) and compares with the expected result.
Tool: ProVerif 2.05, Windows build (download SHA-256 `7b402ce05343e8819c8f05b871105c06d96d5c86556035fa3db4ad24c0820a32`).

Queries, in order: (1) secrecy of data A->B, (2) secrecy of data B->A, (3) A authenticates B (injective),
(4) B authenticates A at first data, (5) B authenticates A at INIT. A is the initiator, B the responder.

## Results (2026-10-20)

`true` means the property holds; `false` means ProVerif found an attack. Every finished result matched its expectation.

| Variant | Attacker | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| `base_psk` | no compromise, PSK set | true | true | true | true | true |
| `base_nopsk` | no compromise, no PSK | true | true | true | true | true |
| `fs` | all long-term keys and the PSK stolen after the sessions | true | true | true | true | true |
| `pq_fs` | X25519 broken, all long-term keys stolen after the sessions | **false** | **false** | true | true | true |
| `quantum_nopsk` | X25519 broken, no PSK | no answer in 1800 s | not run | not run | not run | not run |
| `quantum_psk` | X25519 broken, PSK set | not run | | | | |
| `kem_broken` | ML-KEM broken, no PSK | not run | | | | |
| `kci_nopsk` | B's static keys stolen, no PSK | no answer in 1800 s (attack expected) | not run | not run | not run | not run |

The slowest query is (3), injective agreement: 352-957 s per variant. The others take 6-40 s.
Runs stopped twice when the PC ran low on memory; only finished results are listed.

## Findings

1. **No post-quantum forward secrecy** (`pq_fs`, expected). If X25519 is broken (a future quantum computer
   recording traffic now) and the long-term keys are stolen later, past data can be decrypted. Both ML-KEM
   encapsulations go to static keys (`K_r` in INIT, `K_i` in RESP), so the long-term ML-KEM private keys
   recover both KEM secrets. Fix would need an ephemeral ML-KEM key per handshake. Answers AUDIT_SCOPE question 4.
2. **Classical forward secrecy holds** (`fs`): stealing every long-term key and the PSK after the sessions
   does not reveal past data while X25519 stands.
3. **Mutual authentication holds** in every finished variant, including `pq_fs`: the attacker learns the old
   keys only after the sessions, so it cannot impersonate either side during them.

## Still to run

`kci_nopsk`, `kem_broken`, `quantum_psk`, `quantum_nopsk` (the last with a longer `PROVERIF_TIMEOUT`):

    python run_proverif.py kci_nopsk kem_broken quantum_psk quantum_nopsk > log.txt

Needs several GB of free RAM for query (3).
