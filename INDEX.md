# ioessa-VPN: index

This folder holds three parts. Read the "What it is not" column before using any of them.

## The parts

| Part | Location | What it is | What it is not |
|---|---|---|---|
| Mock VPN controller and web UI | project root (`server.py`, `index.html`, `app.js`, `app.css`, `test_web.py`) | A simulated login, session and tunnel-state controller with a browser UI. Standard library only. | It does not create a tunnel and does not route traffic. Traffic counters are fake, accounts and sessions are in memory, and there is no TLS. |
| Tunnel prototype | `tunnel\` (the `vpn_*` core modules, `vpn_server.py`, `vpn_client.py`, `vpn_keygen.py`, `tun_linux.py`) | A WireGuard-style prototype: one Noise IK handshake over UDP, then ChaCha20-Poly1305 transport. Needs the `cryptography` package and Python 3.9+. | It is not audited and is not wire-compatible with the `wg` tool. It should not protect real traffic. The Linux TUN backend has not been run on a kernel, and there is no Windows TUN (Wintun). |
| Packet-analysis toolkit | `tunnel\analysis\` (`analyze.py`, `capture_run.py`, `pcap.py`, `shim.py`, `slow_network.py`, `tap.py`) | A pcap writer, opt-in capture hook, wire-format analyzer, and leak and loss checks, with its own tests. | It is not part of the tunnel's protection and is not used by the server or client at run time. It only analyzes captures and runs loopback checks. |
| Audit package | `audit\` (`AUDIT_REQUEST.md`, `ioessa-tunnel-audit-2026-10-17.zip`, `MANIFEST.sha256`) | A frozen copy of `tunnel\` for an outside auditor, its SHA-256 manifest, and a quote request ready to send. | It is a snapshot: it goes out of date when any file in `tunnel\` changes. No audit has been commissioned. |

## Running each part

Run all commands from the folder shown in the heading.

### Mock controller (root)

```powershell
python server.py                       # prints a generated password for user "demo"
$env:VPN_DEMO_PASSWORD="your-long-pass-here"; python server.py   # or set your own (12+ characters)
```

Then open http://127.0.0.1:8787. Optional environment variables: `VPN_PORT` (default 8787),
`VPN_LOCKOUT_SECONDS` (60), `VPN_SESSION_TTL` (3600). See `README.md` for the design and known gaps.

Checked here: `python server.py` (with `VPN_PORT` set to a free port) served `GET /` with 200 and refused a bad `Host` header with 403. The `VPN_DEMO_PASSWORD` form printed `Login: demo / (from VPN_DEMO_PASSWORD)`. The generated-password form was not run.

### Tunnel prototype (`tunnel\`)

Setup: `python -m pip install cryptography` (not run here, see note below).

```powershell
# Keys (never stored in source). Prints a private and a public key:
python vpn_keygen.py
python vpn_keygen.py --out my.key     # writes my.key (private) and my.key.pub (public)

# Fingerprint of a peer's public key, to compare over a second channel:
python -c "import base64,hashlib,sys; raw=base64.b64decode(open(sys.argv[1]).read().strip(), validate=True); print(hashlib.sha256(raw).hexdigest())" peer.pub
```

Loopback run (two shells, keys only in environment variables):

```powershell
# Server
$env:IOESSA_VPN_PRIVATE_KEY = "<server private key>"
$env:IOESSA_VPN_PEER_PUBLIC_KEY = "<client public key>"
python vpn_server.py --port 45500 --idle-timeout 30

# Client, in another shell
$env:IOESSA_VPN_PRIVATE_KEY = "<client private key>"
$env:IOESSA_VPN_PEER_PUBLIC_KEY = "<server public key>"
python vpn_client.py --port 45500 --protect 10.8.0.0/24 --packets 3 --roam-after 2
```

Restart-safe replay state (recommended for any server that may restart):

```powershell
python vpn_server.py --port 45500 --state-file C:\ioessa\vpn-state.json
```

Help for every option: `python vpn_server.py --help`, `python vpn_client.py --help`, `python vpn_keygen.py --help`.

Checked here: keygen (`--out` writes both files, a second `--out` to the same name is refused), the fingerprint command, the loopback run above (tunnel came up, three inner datagrams echoed, roaming and the SPD bypass both shown), and `--help` for all three scripts. The `--state-file` flag appears in `--help`; a server was not started with it, so the state-file path is covered only by `test_state.py`.

Linux TUN backend (root or CAP_NET_ADMIN, Linux only, not run here): `--tun linux`, `--tun-name`, `--tun-addr`, `--mtu`, `--tun-route`. The flags appear in `--help`. The netns example in `tunnel\README.md` is written but not run. Do not run it on a machine you cannot reset. It changes routes and devices.

### Packet-analysis toolkit (run from `tunnel\`)

```powershell
python analysis\analyze.py --help          # analyze a pcap of the outer (wire) traffic
python analysis\capture_run.py --help      # run server or client with the opt-in capture hook
python analysis\slow_network.py --help     # loss and latency check of the handshake on loopback
```

Checked here: all three `--help` outputs. Their full runs were not done in this pass.

## Test suites

| Suite | Command (from the folder shown) | Count on this tree | Result |
|---|---|---|---|
| Mock controller | `python -m unittest test_web test_fuzz_web test_web_accounts` (project root). Seed for the fuzz tests: `IOESSA_FUZZ_SEED` | 45 | OK |
| Tunnel core, hardening, lifetimes, PSK, recovery, keys | `python -m unittest` (`tunnel\`) | 267 | OK |
| Tunnel handshake and datagram fuzzing | `python -m unittest test_fuzz` (`tunnel\`). Seed: `IOESSA_FUZZ_SEED` | 4 | OK |
| INIT timestamp model check | `python model_check_init.py` (`tunnel\`), or `python -m unittest test_model_init` | 5 | OK |
| Tunnel, one class | `python -m unittest test_tun.TunLoopTests -v` (`tunnel\`) | 4 | OK |
| Analysis toolkit | `python -m unittest discover -s analysis -p "test_*.py"` (`tunnel\`) | 28 | OK |

The counts are from this finalization pass (2026-10-16). Older counts in the review documents are dated history.

## Review documents

Root:

- `DESIGN_PRINCIPLES.md`: UI review checklist for the mock web UI, based on Krug's *Don't Make Me Think*.
- `SECURITY.md`: how to report a vulnerability (GitHub private vulnerability reporting; best-effort replies, 90-day disclosure, no bounty).
- `WEB_SECURITY_REVIEW.md`: security review of the mock controller against *The Web Application Hacker's Handbook*, with a status per control and the open web items.

`tunnel\`:

- `THREAT_MODEL.md`: threat model for the tunnel, with STRIDE tables, a crypto checklist, and what is not verified.
- `CRYPTO_REVIEW.md`: review of the crypto in `vpn_core.py` against *Real-World Cryptography*, findings F1 to F9.
- `KEY_LIFECYCLE.md`: lifecycle of the static keys (generation, pinning, rotation, revocation) against *Bulletproof TLS and PKI*.
- `NETWORK_SECURITY_REVIEW.md`: network security review against Stallings, *Network Security Essentials* (ESP, firewall checklist, Linux TUN).
- `OPERATIONS_REVIEW.md`: logging, placement, firewall, privileges and other operational gaps.
- `RANDOMNESS_REVIEW.md`: where randomness comes from, how it is used, and the PSK and fork or snapshot risks.
- `RFC7296_REVIEW.md`: mapping of the retransmission rules (RFC 7296 sections 2.1 and 2.4) to the code.
- `SANS_REVIEW.md`: SANS SEC401.1 course points mapped to the tunnel, with ranked findings.
- `SECURITY_ENGINEERING_REVIEW.md`: Anderson, *Security Engineering*, chapter by chapter; open items ranked in section 9.
- `SIDE_CHANNEL_REVIEW.md`: timing and cache side channels, and the audit of secret comparisons.
- `SRE_REVIEW.md`: review against *Building Secure and Reliable Systems* (DoS, logging, restart, retries, timers); section 11 lists the gaps left open.
- `WIREGUARD_COMPARISON.md`: gap analysis against the WireGuard paper; most gaps are now closed (status note at the top).
- `ZERO_TRUST_REVIEW.md`: zero-trust principles against the tunnel; the verdict is "not zero trust".
- `README.md`: the tunnel's user documentation, including the restart and replay section and the verified and unverified list.

## Open issues

- `tunnel\OPEN_ISSUES.md`: consolidated list of open items from all review documents, grouped by protocol and crypto, operations and privileges, testing and verification, and documentation.
- Within each review document: the status tables and "open" or "gaps" sections (for example `SRE_REVIEW.md` section 11, `SECURITY_ENGINEERING_REVIEW.md` section 9, and the web table in `WEB_SECURITY_REVIEW.md`).
- The tunnel's own list: `tunnel\README.md`, section "Open gaps" and "Not done or not verified".

## Notes

- The tunnel requires `cryptography`. The test runs here used `cryptography` 50.0.2 on Python 3.13.14. The package install was not re-run, because `python -m pip` did not return in this environment.
- The bash blocks in `tunnel\README.md` (the netns example) are Linux commands. `python3` resolves on this Windows machine, but those blocks were not run.
