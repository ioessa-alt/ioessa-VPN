# ioessa VPN tunnel prototype

A small WireGuard-style VPN prototype, following Donenfeld, "WireGuard: Next Generation Kernel
Network Tunnel" (NDSS 2017). Each side has a long-term Curve25519 keypair. One 1-RTT Noise IK
handshake gives transport keys. The handshake is hybrid: each node also has a static ML-KEM-768
(FIPS 203) key, so the transport keys stay secret if either X25519 or ML-KEM-768 holds, and a peer must hold both keys to impersonate it. See `CRYPTO_REVIEW.md` F10.
Inner IPv4 datagrams are encrypted with ChaCha20-Poly1305 and carried over UDP.

The post-quantum step protects confidentiality against a future quantum computer that records
traffic today. It does not protect authentication: the static keys are still X25519, so a future
quantum computer could impersonate a peer. See `CRYPTO_REVIEW.md` section "Post-quantum hybrid".

This is a prototype for learning and testing. It is not audited, it is not wire-compatible with
the `wg` tool, and it should not protect real traffic.

## Files

- The protocol core, one module per part (dependencies flow down this list):
  - `vpn_constants.py`: wire sizes, timers, profiles, labels, env var names.
  - `vpn_errors.py`: `ESPError`, `RekeyRequired`, `HandshakeError`, `StateFileError`.
  - `vpn_crypto.py`: hash, MAC, KDF, AEAD, X25519 and ML-KEM wrappers, key encoding.
  - `vpn_keyfiles.py`: key, peer and PSK loading, with file permission checks.
  - `vpn_state.py`: the restart state file (`TimestampStore`).
  - `vpn_handshake.py`: handshake (Noise IK), mac1, mac2 and cookies.
  - `vpn_ip.py`: SPD (`Policy`) and IPv4 helpers.
  - `vpn_transport.py`: transport (`seal_data`, `open_data`) and the replay window.
  - `vpn_node.py`: `Peer` and `Node`: roaming, keepalive, rekey, budgets.
  - `vpn_tun.py`: the `TunDevice` interface and `QueueTun`.

  These replace `vpn_core.py` (split 2026-10-17, see `SPLIT_PLAN.md`). In tests, patch a name in the module
  that looks it up, for example `vpn_node.make_response`.
- `vpn_server.py`: UDP tunnel endpoint (responder). Binds 127.0.0.1 by default.
- `vpn_client.py`: UDP tunnel client (initiator).
- `vpn_keygen.py`: makes a static keypair (prints it, or writes it to a file).
- `tun_linux.py`: Linux TUN backend (`LinuxTun`) and the MTU math. Standard library only.
- `test_vpn.py`: unit tests for the core (`python -m unittest`).
- `test_tun.py`: tests for the TUN backend, its validation and MTU math, and the TUN loops
  (no root needed; runs on Windows too).
- `test_state.py`: the restart state file (`TimestampStore`) and the server's refusal to start with a malformed one.
- `test_hardening.py`: source-address claims, the endpoint on INIT, timers under load, key-file modes,
  and the client's server-key candidates.
- `test_fixes.py`: regression tests for the all-zero PSK check and the Windows connection-reset handling.
- `test_randomness.py`: tests for the randomness sources (OS RNG for keys, nonces and cookie secrets; no `random` module).
- `THREAT_MODEL.md`: threat model, STRIDE tables, crypto checklist, and what is not verified.
- `OPEN_ISSUES.md`: consolidated list of open issues from the review documents.
- `analysis/`: packet-analysis toolkit (pcap writer, opt-in capture, wire-format analyzer, leak and loss checks). See `analysis/`.

Requires Python 3.9+ and `python -m pip install cryptography`.

## Keys

Keys are never in source. Each side needs its own private key and the other side's public key.
Keys are base64. X25519 keys are 44 characters. ML-KEM private keys are 88 characters (a 64-byte seed), and the ML-KEM public key is 1580 characters, so peers exchange `<X25519>:<ML-KEM>` entries, which the `.peer` file holds.

```powershell
python vpn_keygen.py --out my.key     # writes my.key, my.key.pub, my.key.kem, my.key.kem.pub and my.key.peer
python vpn_keygen.py --stdout         # prints the private keys to the terminal (secret; shell history keeps them)
```

Running `vpn_keygen.py` with no option refuses to run. A private key is printed only with `--stdout`.

| Setting | Env var | File option |
|---|---|---|
| This side's private key | `IOESSA_VPN_PRIVATE_KEY` | `--key-file` (or `IOESSA_VPN_PRIVATE_KEY_FILE`) |
| Peer's entries | `IOESSA_VPN_PEER_PUBLIC_KEY`, each `<X25519>:<ML-KEM>` or `<X25519>:<ML-KEM>:<PSK hex>` (comma separated; the client tries every entry at once and keeps the one that answers) | `--peer-key-file` |
| Per-peer PSK (hex, 32+ bytes, optional) | the third field of a peer entry. Without it, the entry uses the default below | n/a |
| Default PSK (hex, 32+ bytes) | `IOESSA_VPN_PSK`, used only with `--use-psk`, for entries with no PSK field | n/a |
| Handshake replay state (server) | `IOESSA_VPN_STATE_FILE`, else the default location (`%LOCALAPPDATA%\ioessa-vpn\state.json` on Windows, `~/.local/state/ioessa-vpn/state.json` elsewhere) | `--state-file`; `--no-state-file` turns it off |
| Key age limit (optional, off by default) | `IOESSA_VPN_MAX_KEY_AGE_DAYS` | `--max-key-age-days` |

The PSK is off by default. It must be set on both ends if used.

Keys are configured by hand, with no certificates or PKI. A wrong key fails the handshake with a
generic message. To check a public key that came from the other side, compare fingerprints over a
second channel (phone, in person), not over the channel that delivered the key:

```powershell
python -c "import base64,hashlib,sys; raw=base64.b64decode(open(sys.argv[1]).read().strip(), validate=True); print(hashlib.sha256(raw).hexdigest())" peer.pub
```

The fingerprint is SHA-256 over the 32 raw key bytes. The reasoning is in `NETWORK_SECURITY_REVIEW.md`.

A private key file (`--key-file`) must not be readable or writable by group or others. On POSIX
the program refuses to load one that is (`chmod 600` fixes it). On Windows the program reads the
file's ACL with `icacls` and refuses to load it if any principal other than your account, SYSTEM
or Administrators has access. It also refuses if `icacls` fails. Principal names are matched in
English, so on a localized Windows the check may refuse until you remove the extra entries.

## Protocol version, per-peer PSK, key age

- **Wire version 2.** Byte 1 of every datagram is the protocol version (`WIRE_VERSION`). Bytes 2 and 3
  are reserved and must be zero. Any other version is dropped before parsing, so a version 1 peer
  cannot talk to a version 2 server. Both sides must upgrade together.
- **PSK per peer.** Each peer can have its own pre-shared key, given as the third field of its peer
  entry (`<X25519>:<ML-KEM>:<PSK hex>`). The PSK is mixed in after the initiator's static key, so the
  responder learns which peer it is talking to before it needs that peer's PSK. A wrong PSK fails
  silently, like any other failure, and the local log names the step. `mac1` and the cookie no longer
  depend on the PSK.
- **Freshness window.** An INIT timestamp must be within 180 s of the responder's wall clock
  (`FRESHNESS_WINDOW`). A correctly signed INIT that is held back and replayed later is refused, even
  when the responder has no newer INIT on record.
- **Global INIT budget (self-tuning).** INITs that pass mac1 share a node-wide budget. It starts at 200
  per second, rises 25% in any window that refused something (up to 2000 per second), and falls to twice
  the admitted rate after three quiet windows (down to 50 per second). Junk that fails mac1 costs nothing.
- **Windows TUN (Wintun).** `--tun windows` uses `tun_windows.py`, which loads WireGuard's `wintun.dll`.
  The DLL must be signed by WireGuard LLC (check with `Get-AuthenticodeSignature`). Put it at
  `%LOCALAPPDATA%\ioessa-vpn\wintun\wintun.dll`, or set `IOESSA_WINTUN_DLL`. Creating the adapter needs an
  administrator shell. Check the driver with `python tun_windows.py --selftest` from an elevated shell.
  `--drop-to` is not supported on Windows.
- **IPv6 outside the tunnel.** The tunnel carries IPv4 only. Run `ipv6_guard.ps1 -Enable` from an
  elevated shell to add a firewall rule that blocks outbound IPv6 to the global, unique-local, link-local
  and multicast ranges. `-Disable` removes it. Link-local traffic is blocked too, so IPv6 neighbour discovery stops.
- **Default source policy.** A peer without an explicit `allowed_ips` may only send inner packets
  from `10.8.0.0/24`. Set `allowed_ips` per peer for anything else.
- **Key age limit (off by default).** `--max-key-age-days N` (or `IOESSA_VPN_MAX_KEY_AGE_DAYS`) refuses to
  start with a static key older than N days. The age comes from the `.created` file that
  `vpn_keygen.py --out` writes next to the key. A key with no valid date is refused while the limit is set.
  Choose N from your own policy. NIST SP 800-57 Part 1 has suggested cryptoperiods by key type; that document is not in this folder, so the figure is not checked here.

## Restart and replay state

The server remembers, for each peer, the timestamp of the last accepted handshake, so a captured
handshake cannot be replayed. The state file is on by default, at the location in the table above.
Pass `--state-file PATH` to choose another place, or `--no-state-file` to keep the memory in RAM only,
which loses it on restart:

```powershell
python vpn_server.py --port 45500 --state-file C:\ioessa\vpn-state.json
```

- The file is JSON: each peer's public key (base64) maps to its last timestamp (hex), plus an
  integrity tag under the key `_mac`. The tag is an HMAC keyed by a value derived from this server's
  private key, so it does not need a second secret. The file holds public keys and the tag, never private keys.
- **A file that fails the tag check stops the server** with `integrity check`. This catches an edited
  file, or one copied from another server. It does not catch an older copy of this server's own file
  (rollback). Keep the file out of backups you might restore.
- Each handshake is written to the file before the server sends its response. The write is atomic
  (temp file in the same folder, fsync, then rename). If the write fails, the handshake is refused
  and no response is sent.
- At start, a missing file means an empty state, and the file is created on the first handshake.
  An unreadable or malformed file stops the server with `error: state file ... is malformed`. The
  server never resets the file, because a reset would reopen replay. Fix or move the file yourself.
- **With `--no-state-file`, the server prints a warning at start.** After a restart, a captured
  handshake is accepted again, and the responder creates a pending session for it. The replayer
  gets a response it cannot use. The peer's endpoint does not move on the handshake, so the replay
  cannot redirect the tunnel. Replay protection across a restart needs the state file.
- The operator must keep the file. Deleting it, or restoring an older copy, reopens the window.
  Keep it on local disk, readable only by the server account, and use one file per server process.

## Run (loopback)

```powershell
# Server: its own private key, and the client's public key
$env:IOESSA_VPN_PRIVATE_KEY = "<server private key>"
$env:IOESSA_VPN_PEER_PUBLIC_KEY = "<client entry: X25519 public key>:<client ML-KEM public key>"
python vpn_server.py --port 45500 --idle-timeout 30

# Client, in another shell: its own private key, and the server's public key
$env:IOESSA_VPN_PRIVATE_KEY = "<client private key>"
$env:IOESSA_VPN_PEER_PUBLIC_KEY = "<server entry: X25519 public key>:<server ML-KEM public key>"
python vpn_client.py --port 45500 --protect 10.8.0.0/24 --packets 3 --roam-after 2
python -m unittest
```

`--roam-after N` changes the client's UDP port before packet N, to show roaming. Port 4500 is
refused on some Windows machines, so the examples use 45500. `--show-payload` prints decrypted
plaintext to the console. It is UNSAFE for production and only for demos; never use it where
output is kept or shared. See `OPERATIONS_REVIEW.md`.

## Linux TUN backend (root, Linux only)

`--tun linux` replaces the in-memory demo with a real TUN device. The server and client then
carry the packets the host sends to the tunnel prefix. Options: `--tun-name` (default `ioessa0`),
`--tun-addr` (default `10.8.0.1/24` on the server, `10.8.0.2/24` on the client), `--mtu` (default
1400), and `--tun-route` (repeatable; default `10.8.0.0/24` on the server and the `--protect`
prefix on the client). The client also takes `--local-bind` for the address of its UDP socket.

What it does (`tun_linux.py`): opens `/dev/net/tun`, attaches the device with `TUNSETIFF`
(`IFF_TUN | IFF_NO_PI`), and configures it with `ip addr add`, `ip link set ... mtu`, `ip link set ... up`,
and `ip route add` (argument lists, never a shell). Names, addresses, MTU and routes are validated
first. The default route is refused. The device is non-persistent: it and its routes disappear
when the process exits.

**Revoke a peer without restarting.** When the server reads its peers from `--peer-key-file`, it re-reads that file about every 5 seconds. A key removed from the file loses its sessions at once. A new key is added and configured. A file that fails to parse, or is empty, is refused and the current peers stay, so removing every peer needs a restart. Peers from `IOESSA_VPN_PEER_PUBLIC_KEY` are fixed until restart (`peer_reload.py`, `test_reload.py`).

**Drop root after setup.** `--drop-to USER` (server and client, with `--tun linux`) switches the process to `USER`
after the TUN device, address, routes and UDP socket are set up. It drops the supplementary groups,
then the group and user IDs, and then checks that root cannot be regained. It refuses to drop to
root. The TUN descriptor stays usable after the drop.

**Needs root** (or `CAP_NET_ADMIN`) and a Linux kernel with the `tun` module. Off Linux, `LinuxTun`
raises a clear error. The default `--tun queue` needs neither.

Use key files for `sudo`, since `sudo` drops environment variables. Two hosts or two namespaces
are needed, because two devices with the same subnet cannot share one host. Example with a veth
pair (run as root; the commands are not yet run, see "Verified" below):

```bash
python3 vpn_keygen.py --out srv.key; python3 vpn_keygen.py --out cli.key   # then exchange the .peer files
ip netns add vpnsrv
ip link add veth-cli type veth peer name veth-srv
ip link set veth-srv netns vpnsrv
ip addr add 10.200.0.1/24 dev veth-cli && ip link set veth-cli up
ip netns exec vpnsrv sh -c 'ip addr add 10.200.0.2/24 dev veth-srv && ip link set veth-srv up && ip link set lo up'
ip netns exec vpnsrv python3 vpn_server.py --tun linux --bind 10.200.0.2 --port 45500 \
    --key-file srv.key --kem-key-file srv.key.kem --peer-key-file cli.key.peer --tun-addr 10.8.0.1/24
python3 vpn_client.py --tun linux --server 10.200.0.2 --port 45500 --local-bind 10.200.0.1 \
    --key-file cli.key --kem-key-file cli.key.kem --peer-key-file srv.key.peer --tun-addr 10.8.0.2/24 --protect 10.8.0.0/24
# in a third shell, from the client host:
ping -c 3 10.8.0.1
```

Clean up with `ip netns del vpnsrv` and `ip link del veth-cli`.

**MTU.** The tunnel adds 65 bytes to each inner packet on the wire: outer IPv4 (20), UDP (8), the
DATA header (16), padding (0 to 3), the trailer (2) and the Poly1305 tag (16). `tun_linux.max_tun_mtu`
gives 1400 on a 1500-byte link. That is also the `MAX_INNER` limit in `vpn_constants.py`, because
`seal_data` refuses larger inner packets. The test `test_overhead_matches_packets_sealed_by_the_core`
checks the 65 bytes against real sealed packets.

**Routing and identity.** A peer's `allowed_ips` is set to the tunnel routes in TUN mode, so each
side accepts and sends only the tunnel prefix (cryptokey routing). Every peer on the TUN server gets
the same routes, so the server refuses to start with two or more peers (one peer per TUN server
until per-peer routes are configurable). The queue mode demo keeps the default any-source list. IPv6 frames from the device are
dropped, because the tunnel carries IPv4 only. The host can still send IPv6 outside the tunnel.

## Firewall and network setup (documentation only)

The program changes only its own TUN device and that device's routes. It never edits the firewall.
The table and rules below are a checklist for a real endpoint. None of them was applied or run
here, and the Linux backend has not run on a kernel (see "Verified and not verified").

| Item | Default (examples use 45500) | Where it applies |
|---|---|---|
| Outer UDP port | `--port`, default 4500 | Server: inbound UDP to this port on the public interface. Client: outbound UDP to it. |
| Peer address | the client's public IP. Roaming can change the client's source port or IP, and a changed IP needs a rule change | Server, public interface |
| Tunnel prefix | `10.8.0.0/24` (`--tun-route`; the client's `--protect`) | Routed to the TUN device by the program. Rules on the TUN interface use this prefix |
| TUN interface | `ioessa0` (`--tun-name`); in the netns example, the server's public side is `veth-srv` inside `vpnsrv` | Interface names in the rules below |
| Bind address | `--bind`, default 127.0.0.1 | Set `--bind` to the public address. Avoid 0.0.0.0 |

Rules to consider on Linux, with a default-deny inbound policy (Stallings, Ch. 12, default-discard):

1. Accept inbound UDP to the server port from the client's IP. Drop the rest of inbound by default.
2. Anti-spoofing: on the public interface, drop packets whose source is in the tunnel prefix. Ch. 12
   gives this countermeasure for IP address spoofing: discard packets with an inside source address
   that arrive on an external interface.
3. Allow ICMP echo on the TUN interface if you want to ping the tunnel address, since the default
   drop would block it.
4. Allow ICMP "fragmentation needed" on the public path. Inner MTU is 1400 on a 1500-byte link, and
   blocking this message can cause black holes. The SEC401.1 course covers it in its ICMP section
   ("Fragmentation needed and DF flag set"), checked against the OCR text on 2026-10-17.
5. Forwarding is needed only if the endpoint carries traffic to other networks. Then set
   `net.ipv4.ip_forward=1`, allow FORWARD between `ioessa0` and the public interface, and add NAT if
   clients should reach the internet. This is not tested here.

Example only, not applied (iptables, server side, public interface `eth0`, client `203.0.113.10`):

```bash
iptables -A INPUT -i eth0 -p udp --dport 45500 -s 203.0.113.10 -j ACCEPT
iptables -A INPUT -i eth0 -s 10.8.0.0/24 -j DROP
iptables -A INPUT -i ioessa0 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i eth0 -p icmp --icmp-type fragmentation-needed -j ACCEPT
```

The client needs outbound UDP to the server port and the same ICMP rule. Replace the addresses and
interfaces to match your hosts.

## Design

- **Handshake (V-D1 to V-D3).** Noise IK with the paper's construction: chaining key, hash,
  MixHash and MixKey steps, and ChaCha20-Poly1305 over the transcript hash. Messages are INIT
  (type 1, 1236 bytes), RESP (type 2, 1180 bytes) and COOKIE (type 3). The initiator's static key
  is encrypted in INIT (identity hiding). INIT carries an ML-KEM-768 ciphertext to the responder's
  static key, and RESP carries one to the initiator's static key. Both sides mix the ML-KEM shared secret into
  the chaining key before the transport keys are derived. Kdf is the paper's HKDF over HMAC-BLAKE2s, written from the paper's definition
  because `cryptography` has no BLAKE2s. BLAKE2s itself comes from `hashlib`.
- **Replay protection for handshakes (V-A).** Each INIT carries an encrypted TAI64N timestamp. The
  responder keeps the greatest one per peer and drops anything not greater. The initiator's
  timestamps strictly increase. With `--state-file`, that value is persisted before the response
  is sent, so the check survives a restart (see "Restart and replay state").
- **DoS (V-C, V-D4, V-D7).** Every handshake message has mac1, keyed by the receiver's public key
  (and the PSK, if used). Without a valid mac1 there is no reply and no state. Under load, an INIT
  without a valid mac2 gets a cookie reply and no DH work. The cookie is a MAC of the source IP
  under a secret that rotates every 120 s. It is encrypted with a key from the responder's public
  key and a random salt, and bound to the INIT's mac1.
- **Limits of the DoS defences.** Replies are smaller than the request that caused them, so the
  tunnel does not amplify a spoofed source. A flood that fills the link or the CPU from many sources
  is not stopped: the per-source INIT budget limits handshake work from one real address, but there is no bandwidth cap and spoofed sources are not bounded, so filter upstream.
- **Key compromise.** A leaked initiator key does not let an attacker pose as the responder. A leaked
  responder key lets an attacker pose as any known client, unless a PSK is set (the PSK is needed
  too). Section 7 of THREAT_MODEL.md lists what the tunnel does not stop.
- **Transport (V-D6).** Header: type, reserved bytes, receiver index, 64-bit counter (16 bytes).
  The header is authenticated as associated data. Payload: the inner datagram plus the ESP-style
  trailer (padding to 4 bytes, pad length, next header). An empty inner datagram is a keepalive.
- **Replay window.** 64 packets, updated only after AEAD verification.
- **Roaming (II-A).** The endpoint follows the source of the latest packet that passes the replay
  check, the AEAD check and the inbound source check. A forged or refused packet cannot move it. An
  INIT does not move it: the endpoint follows the first authenticated packet of the new session.
- **Cryptokey routing (II, III step 4).** Outbound: the SPD (`Peer.spd`) picks the peer and action
  (PROTECT, BYPASS, DISCARD). Inbound: a decrypted inner source must fall in `Peer.allowed_ips`.
  The default is any source, so configure it for real use.
- **Timers.** `poll()` (rekey, expiry, keepalive, handshake retries) runs once per tick (1 s) in
  both serve loops, even under steady traffic. Session expiry therefore takes effect within one tick.
- **Keepalive (VI-E).** After authenticated data with nothing to send, an empty packet is sent
  once the period has passed (default 10 s, `--keepalive`, 0 disables).
- **Rekey (VI-B).** Either side starts a new handshake after 120 s of use or at the message limit,
  whichever first. The message limit is 2^32 - 1024, which is stricter than the paper's example
  of 2^60. Initiations are at least 5 s apart. A due rekey first waits a random 0 to 5 s, so two
  peers do not fire together. If both still start at once, the INIT with the lower ephemeral public
  key wins (both sides see both keys, so no extra round trip is needed). The other side drops its
  attempt and answers (RFC 7296 2.8.1). The responder promotes its new session on its first
  authenticated data. The initiator sends a confirmation keepalive right after the response.
- **Handshake retries.** A pending INIT is sent again after 5 s, then 10 s, then 20 s, capped at
  20 s, each gap varied by +/-20 %. The attempt is dropped 90 s after it started, so a dead server
  fails in finite time. A retry builds a new INIT (it is not bitwise identical to the first, see
  RFC7296_REVIEW.md).
- **Demux.** Byte 0 is the message type, and bytes 1 to 3 are zero. Anything else is dropped.
- **Bounds.** Inner datagram at most 1400 bytes, outer at most 1600 bytes, UDP buffer 2048 bytes.

## Verified and not verified

**Verified (run here, on Windows, Python 3.13 with `cryptography` 50.0.2):**

- `python -m unittest`: 243 tests pass (run from `tunnel\`; the count was checked on the current tree).
- `python -m unittest discover -s analysis -p "test_*.py"`: 28 tests pass.
- A loopback handshake over real UDP with keys only in environment variables: the tunnel came up,
  three inner datagrams were echoed, and the SPD bypassed one (run on this tree).
- Argument validation for names, addresses, MTU and routes, and that invalid input builds no
  `ip` commands. `ip` is called with an argument list and `shell=False`, checked with a mock.
- MTU math: 65 bytes of overhead, checked against real packets sealed by `vpn_transport.seal_data`
  for every inner length from 20 to 1400 (34 to 37 bytes of extra UDP payload, plus 28 for the
  outer IP and UDP headers).
- ioctl constants: `TUNSETIFF == _IOW('T', 202, int) == 0x400454CA`, `IFF_TUN`, `IFF_NO_PI`,
  and the 40-byte `struct ifreq` layout. These are checked against the `_IOW` encoding and the
  struct rules, not against a Linux header on disk, because none is available here.
- `LinuxTun` refuses to start off Linux with a clear error, and the modules import on Windows.
- The TUN loops (`serve_tun`, `run_tun`) over real loopback UDP, with a socket-backed stand-in for
  the device: a host packet crosses the tunnel both ways, and a non-IPv4 frame is kept out.
- CLI errors: `vpn_server.py --tun linux` and `vpn_client.py --tun linux` print one clear error on
  Windows, and `--mtu` without `--tun linux` is refused.

**Not verified:**

- **The Linux TUN device itself.** It was not created, configured or pinged on any Linux kernel.
  WSL is not installed on this machine, and no Docker, Podman or VM is present. Nothing was
  installed or changed in the Windows environment to try. The book (Ch. 2 and Appendix B) says
  `ip tuntap` uses IOCTLs, which is the approach taken here. The `TUNSETIFF` value and `ifreq`
  layout are from memory of `linux/if_tun.h`, not read from a header, so the first real run
  is the test of them.
- **The netns example above.** The steps are written but not run.
- **Wintun (Windows).** Not implemented and not run.

## Not done or not verified

- **Wintun / Windows TUN adapter: not implemented.** `TunDevice` is the interface, `QueueTun`
  is the in-memory implementation, and `LinuxTun` is the Linux one. Nothing has run against a
  Windows adapter.
- **Real network:** tested on 127.0.0.1 only. No NAT traversal beyond roaming, no packet-loss
  testing beyond the unit tests, no path MTU work.
- **Not interoperable** with the `wg` tool. The mac1 and cookie labels come from the WireGuard
  reference protocol.
- **Not implemented:** per-peer PSKs (one PSK for all peers), a bandwidth cap, zeroing of
  secrets (Python cannot guarantee it), ESN, IPv6, transport mode, certificates.
- **Not verified:** formal proof, coverage-guided fuzzing (only a seeded mutation test exists),
  timers on a real clock (tests use a fake clock).

## Open gaps

These are known and not fixed:

- **Per-source limit.** Built for INIT handshake work (`SRC_INIT_RATE`, `SRC_INIT_BURST`). A flood from many spoofed sources still costs CPU and bandwidth (THREAT_MODEL U-D1, P-D3, U-D5).
- **Privilege drop after TUN setup.** `--tun linux` keeps root or CAP_NET_ADMIN for the whole run. It cannot be
  tested on this machine.
- **Runtime revocation without a restart.** `Node.remove_peer` works in the library, but no command path calls
  it. Removing a key from the peer file takes effect at the next restart. A reload path is needed.
- **Per-peer routes on the TUN server.** Until they exist, the TUN server takes one peer.
- **Per-packet session age.** Expiry is enforced by `poll()`, once per tick. The receive path does not check
  session age itself.
