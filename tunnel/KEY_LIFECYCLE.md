# Key lifecycle: tunnel prototype against *Bulletproof TLS and PKI* (Ristić)

Scope: the static Curve25519 keys in `vpn_core.py`, `vpn_keygen.py`, `vpn_server.py` and `vpn_client.py`.
Read first: `THREAT_MODEL.md`, `NETWORK_SECURITY_REVIEW.md`, `CRYPTO_REVIEW.md`, `OPERATIONS_REVIEW.md`.
Not changed: wire format, protocol, handshake, key files. Not built: CA, PKI, certificates.

Book references are line numbers in the extracted text (`scratchpad\bulletproof.txt`). Chapter and page
are given where the text shows them. Only the passages cited here were read.

Key facts about the code, used below:
- The server's peer table is built once at startup from `load_peer_publics()` (`vpn_server.py` `main`).
  `Node.peers` is written only by `add_peer` and, after this change, `remove_peer`. No code path reloads it.
- The client pins one server key: `server_pub = load_peer_publics(args.peer_key_file)[0]` (`vpn_client.py` `main`, line 181).
  A second key in the client's file is ignored without a message.
  **Stale (fixed later):** the client now tries every configured server key and keeps the one that answers
  (`handshake_any`, tests `ClientServerKeyTests` in `test_hardening.py`; see section 5, gap 2). The two lines above describe the old code.
- A wrong key fails silently at the responder. `_on_init` returns without a reply when mac1 fails, and it
  logs one generic line when the key is unknown (`HS_FAIL`).

## 1. Lifecycle table

| Stage | What the tunnel does today (file, function) | What the book recommends | Gap matters here? |
|---|---|---|---|
| Generation | `vpn_keygen.py` `main` calls `generate_keypair()` (X25519, OS RNG). `--out` creates the private file with `O_EXCL` and mode 0600 (ignored on Windows). Without `--out` it prints the private key to stdout (line 28). | Generate a new private key at each renewal (L14290). Treat keys as a liability; track creation dates (L14279-14283). | Low. Stdout printing exposes the secret in terminal scrollback. Use `--out`. Key creation date is not recorded. |
| Distribution | Manual copy. Private key from `--key-file` / env `IOESSA_VPN_PRIVATE_KEY`. Peer public key from `--peer-key-file` / env `IOESSA_VPN_PEER_PUBLIC_KEY` (`load_static_private`, `load_peer_publics`). The README gives a SHA-256 check to run over a second channel. | Pinning is safe when you yourself decide how the pinned keys are handed out (L13747-13750). Only pin to material you control (L13744-13746). | Fits the prototype. The fingerprint check is manual and optional. |
| Pinning / trust | Each side pins the other's raw X25519 public key and nothing else. Server pins each client key in `add_peer`. Client pins the server key. Both sides check key format and reject low-order points (`public_key_from_b64`, `_is_low_order`). There is no CA. | Pin public keys, not certificates, when you control both ends (L13689-13692). Keep a backup key online-ready (L13827-13831). Build an update mechanism for pins (L13808-13816). | Fits. No backup server key exists, because the client reads only `[0]` (see gap 2). |
| Trust on first use | Not used. Keys must be configured before first contact. An unknown client key gets no reply (`Node._on_init`). | HSTS gives no protection on first access (L13306-13311). SSH uses TOFU (L13630-13632). | Fits. The tunnel avoids a first-use window by design. Cost: keys must be exchanged before use. |
| Rotation | Manual. No procedure in the code or docs before this file. Overlap works for client keys (the server accepts several). The client tries each configured server key, so overlap works on both sides (fixed; see section 5, gap 2). Section 3 gives the steps. | Rotate online keys frequently and promote backups (L13827-13831). Change keys after an incident, when staff leave, and when a new certificate is obtained (L14279-14282). | Medium. Rotation is possible, but the server-key cut-over needs a coordinated window. |
| Revocation | None at runtime. The allow-list is the peer file, and it is read only at startup. Removing a key needs a server restart. | Assume any certificate can be revoked (L13782-13783). CRLs are block lists with freshness and privacy problems (L7796-7802, L7814-7821). OCSP stapling has had implementation problems, and must-staple is not widely implemented (L4688-4707). | Real gap. See section 2. The allow-list avoids CRL freshness problems, but it has no fast removal. |
| Compromise response | No written procedure. Client key leak: remove it from the server file and restart. Server key leak: rotate and update every client. Section 3 gives the steps. Forward secrecy is per session (CRYPTO_REVIEW F5), so old traffic is not exposed by a static key leak alone. | Change keys after a breach (L14279-14282). Do not share keys across unrelated systems (L14274-14277). Deleting old keys matters most without forward secrecy (L14283-14289). | Medium. Procedure is now written. Live revocation is not possible without restart. |
| Expiry | Identity keys never expire. Sessions do: `REKEY_AFTER_TIME` 120 s, `REJECT_AFTER_TIME` 180 s, removed after 3 x 180 s (`vpn_core.py` constants, `Node._expire`). Cookie secret rotates at 120 s. | Certificate lifetime was cut to 398 days (L4657-4661). The book sees short-lived certificates as a long way from common use (L4705-4707). Frequent rotation needs automation (L4662-4665). | Low. No key age policy. Session expiry is already short. |
| Session keys (context) | Fresh ephemeral X25519 per handshake; transport keys from `_transport_keys`. A session is rekeyed every 120 s when used. | Session resumption with DHE (`psk_dhe_ke`) keeps forward secrecy. 0-RTT is replayable (L2201-2204, L2644-2651). | Fits. No resumption and no early data, so no 0-RTT replay surface. |

## 2. Revocation and compromise: what happens today

Question: if a client's private key leaks, can the server stop accepting it without a code change?

Answer before the fix: **only by restarting the server with the key removed from its peer file.** There was
no runtime path. Removing a key from the file does nothing until restart.

Probe (scratch copy of `vpn_core.py`, not the real tree). Deleting the peer from the table did not drop its session:

```
before removal: b'E\x00\x00"...\x08\x00\x01before removal'
after del b.peers[...]: b'E\x00\x00!...\x08\x00\x01after removal' []
session still in b.sessions: 1
```

So the gap was real: any code that removed a peer from `node.peers` would leave its session live, and packets from
the removed key still decrypted. The session table `Node.sessions` is separate from the peer table.

Fix (small, clear): `Node.remove_peer(pub)` in `vpn_core.py`. It pops the peer, drops its pending handshake,
and removes its current, previous and next sessions from `Node.sessions`. Unknown keys are a no-op.

Tests: `RevocationTests` in `test_vpn.py` (4 tests):
- `test_removed_peer_session_is_dropped`: an established session's packets are refused as "unknown index" after removal.
- `test_removed_peer_cannot_handshake_again`: a new INIT from the removed key gets no reply and creates no state.
- `test_remove_pending_handshake_and_unknown_key_is_safe`: pending state is cleared; unknown key is a no-op.
- `test_other_peers_keep_their_sessions`: removing one peer does not affect another.

Mutation check (scratch copy with the session-drop loop deleted): `test_removed_peer_session_is_dropped` and
`test_removed_peer_cannot_handshake_again` both failed (`AssertionError: {...} != {}`). So the tests catch the gap.

What the fix does not do: nothing in the CLI calls `remove_peer`. Server revocation still means: edit the
peer file, restart the server. The restart clears all in-memory sessions, and the removed key is then
rejected at the INIT (the same path the last test exercises in-process). A live reload (for example SIGHUP,
which Windows does not have) would be the next step. It was left out because it needs a reload path and
its own tests.

Compromise of the server key: an attacker holding it can impersonate the server to any client that has
that key pinned. Past sessions stay protected by ephemeral DH, unless an ephemeral key is also exposed
(CRYPTO_REVIEW F5). Response: generate a new server key and update every client (section 3.2).

## 3. Rotation procedure

Commands are those in `vpn_keygen.py`. Tested here in a scratch directory: `--out` wrote both files, a
second `--out server.key` was refused (`FileExistsError`, `O_EXCL`), and the README fingerprint command
ran on the generated `.pub` (64 hex characters). The overlap case was tested end to end: one server
with two client keys accepted both clients (`tunnel up` for each).

Paths and names below are examples. Use PowerShell syntax as in the README.

### 3.1 Client key (no downtime with overlap)

1. Client host: `python vpn_keygen.py --out cli2.key`. This writes `cli2.key` and `cli2.key.pub`. Never use a name that already exists.
2. Send `cli2.key.pub` to the server operator over a second channel. Both sides compare the fingerprint:
   `python -c "import base64,hashlib,sys; raw=base64.b64decode(open(sys.argv[1]).read().strip(), validate=True); print(hashlib.sha256(raw).hexdigest())" cli2.key.pub`
3. Server host: write a peer file with the old and new client keys, one per line:
   `peers.txt` = old `cli.key.pub` line, then new `cli2.key.pub` line. Restart the server with `--peer-key-file peers.txt`.
   The restart drops current sessions. The client re-handshakes within about 120 s (its rekey timer).
4. Client host: start the client with `--key-file cli2.key` (or set `IOESSA_VPN_PRIVATE_KEY_FILE` to it). Expect `tunnel up`.
5. Server host: confirm a `handshake from ... accepted` line for the client.
6. Server host: remove the old line from `peers.txt` and restart the server. The old client now gets
   `error: no handshake response from the server` (silent rejection at INIT).
7. Client host: delete `cli.key` and `cli.key.pub`. On Windows, file deletion does not overwrite the data;
   for a higher bar, overwrite before deleting or use disk encryption.

### 3.2 Server key (flag day, no overlap)

**Stale note (fixed later):** the client used to read only the first server key in its file. It now
tries every configured server key (`handshake_any`, `ClientServerKeyTests` in `test_hardening.py`), so overlap
works on the client side too (section 5, gap 2). The steps below still work; overlap is optional.
The original text was: an INIT encrypted to an old server key gets no reply, so a key could not be rotated with overlap.

1. Server host: `python vpn_keygen.py --out srv2.key`. Send `srv2.key.pub` to each client operator. Check fingerprints over a second channel.
2. Pick a window. Restart the server with `--key-file srv2.key`. Until every client is updated, those clients fail with `no handshake response`.
3. Each client host: restart with `--peer-key-file srv2.key.pub` (or set `IOESSA_VPN_PEER_PUBLIC_KEY`). Expect `tunnel up`.
4. Delete the old server private key from the server host after the cut-over is verified.

### 3.3 Compromise response (either key)

1. Revoke: remove the key's line from the server's peer file, then restart the server. (For a client key only. For the server key, use 3.2.)
2. Issue a replacement with `vpn_keygen.py --out ...` and follow 3.1 or 3.2.
3. Record the incident time and the key's creation date, since the book asks for this (L14279-14282).
   The tunnel has no key-age log, so this record is manual.

## 4. TLS comparison

The book's TLS and PKI practices would add four things. CA-issued identities would give each side a
certificate that anyone can check against a root, so the tunnel would not need to distribute raw keys.
The book notes that a private CA suits a closed set of clients and servers (L13650-13656), and that
pinning is worth its cost mainly for public web sites (L13641-13645). For a two-party tunnel with a
manual trust anchor, a CA adds a root to protect, issuance code, and a revocation problem, with no gain
over pinned keys copied over a second channel. It does not fit. OCSP or CRLs would address revocation, but the
book shows both have freshness and privacy problems (L7796-7821), and the tunnel's allow-list has no such
freshness problem. The real fix for this prototype is a faster removal path (section 2), not OCSP. Short-lived
certificates would remove the need for revocation, but they need automated renewal, which the book calls "still
far off" (L4705-4707) and the tunnel has no service for. Pinning to keys is already in use here, and it is the
right form for a controlled pair (L13747-13750). The gap is the backup key and the update path (L13827-13831,
L13808-13816), which the tunnel does not have. TLS 1.3 resumption with `psk_dhe_ke` (L2201-2204) is an option
for speed, but the tunnel does not need it, since a Noise IK handshake takes one round trip. Its 0-RTT mode
(L2644-2651) should stay out. The book is clear that it can be replayed, and the tunnel has no replay-safe
early data path.

## 5. Gaps, ranked

1. **No runtime revocation.** A leaked client key stays valid until the server restarts. Not fixed (a reload
   path is needed). Mitigation: section 3.3. Medium.
2. **Client used only the first server key** (`vpn_client.py` line 181). Fixed (the line number is from the old code): `handshake_any` gives every
   configured server key its own candidate peer, sends an INIT for each, and keeps the one that answers
   (the others are removed). Tests: `ClientServerKeyTests` in `test_hardening.py`. Rotation overlap now works
   on the client side. The server side already accepted several keys.
3. **No backup server key or pin update path** (L13827-13831, L13808-13816). Not fixed. Low for a prototype.
4. **No key age record or rotation schedule** (L14279-14283). Manual. Low.
5. **Keygen prints the private key without `--out`** (`vpn_keygen.py` line 28). Known in `OPERATIONS_REVIEW.md`. Not changed. Low.
6. **Revocation is not logged.** A removed key looks like any unknown key. Low.

Fixed: revocation of a live session by removing a peer, through `Node.remove_peer` (library level, tested).

## 6. Test results

From `tunnel\`, `python -m unittest`. The count was 127 when this section was first written. Current run, after
the second hardening pass:

```
Ran 170 tests in 15.908s

OK
```

Current run (finalization pass): `Ran 179 tests in 15.744s`, `OK`. The 170 above was the count at the second hardening pass.

Before the change the count was 123. The 4 new tests are `RevocationTests` in `test_vpn.py`.
