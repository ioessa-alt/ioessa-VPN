# Handover: ioessa-VPN (for a new chat)

Read this first. Then read `INDEX.md` (what each part is), `tunnel\OPEN_ISSUES.md` (the list and its status
sections), and `tunnel\SPLIT_PLAN.md` (the next planned task). Nothing here is in git. Do not assume a
file is unchanged: other sessions edit files in this folder.

## 1. What this is

- **Root (`%USERPROFILE%\ioessa-VPN`)**: a simulated VPN controller and web UI (`server.py`, `index.html`,
  `app.js`, `app.css`). Standard library only. It creates no tunnel and routes no traffic. Demo accounts,
  sessions, audit lines, optional HTTPS.
- **Tunnel (`%USERPROFILE%\ioessa-VPN\tunnel`)**: a WireGuard-style prototype with a hybrid ML-KEM-768
  step: the core modules `vpn_constants.py` to `vpn_tun.py` (split out of `vpn_core.py`, which no longer
  exists; see `tunnel\README.md`), `vpn_server.py`, `vpn_client.py`, `vpn_keygen.py`,
  `peer_reload.py`, `tun_linux.py`, `tun_windows.py`, `ipv6_guard.ps1`, `analysis\` (pcap and checks).
  It is not audited and must not protect real traffic (see `AUDIT_SCOPE.md`).

## 2. Current state

Test suites, all passing at the last run:

| Suite | Command | Count |
|---|---|---|
| Tunnel | `python -m unittest` (in `tunnel\`) | 287 |
| Analysis | `python -m unittest discover -s analysis -p "test_*.py"` (in `tunnel\`) | 28 |
| Web | `python -m unittest test_web test_fuzz_web test_web_accounts test_web_tls` (in the root) | all pass |
| INIT model check | `python model_check_init.py` (in `tunnel\`) | replay safety holds |

Wire format: version 2 (`WIRE_VERSION`). Byte 1 is the version. Peers must upgrade together.

## 3. Decisions already made (do not reopen without asking)

- **No per-message ratchet.** Per-session rekey (120 s) is kept (OPEN_ISSUES item 3).
- **PSK per peer**, given as the third field of a peer entry (`<X25519>:<ML-KEM>:<PSK hex>`).
  Mixed in after the initiator's static key is known. `mac1` and the cookie do not use it.
- **Freshness window 180 s** on INIT timestamps (wall clock). Expect clock-skew complaints if NTP is off.
- **Global INIT budget** self-tunes between 50 and 2000 per second, starting at 200 (see `tunnel\README.md`).
- **State file on by default** at the user location, with an HMAC tag keyed from the server's private key.
  Rollback to an older copy is still possible. This is documented, not solved.
- **Key age limit** is off by default. `--max-key-age-days` needs a `.created` file from keygen.
- **Default `allowed_ips`** is `10.8.0.0/24`.
- **Keygen** prints private keys only with `--stdout`.
- **No TLS** on the tunnel's control path (there is none). The web mock has optional HTTPS
  (`VPN_TLS_CERT`, `VPN_TLS_KEY`) and HSTS.
- **Per-peer routes and zero-trust controls deferred** (OPEN_ISSUES items 10, 11, 27, 34, 42).
- **Ratchet, entropy checks beyond length and all-zero, and a bandwidth cap of a fixed size** are not built.

## 4. Open decisions and tasks

**In progress, paused 2026-10-17 (laptop closed).** The user asked for all four; decisions already made:

1. **Formal model (ProVerif).** ProVerif 2.05 Windows build is at `%LOCALAPPDATA%\ioessa-vpn\proverif\proverif2.05\`
   (download SHA-256 `7b402ce0...0a32`). Model: `tunnel\formal\ioessa_handshake.pvt` (template, follows
   `vpn_handshake.py` step by step) and `tunnel\formal\run_proverif.py` (8 attacker variants with expected results).
   - Done for `base_psk`, each query run alone: both secrecy queries true (11-16 s), "B authenticates A at
     first data" true (35 s), "B authenticates A at INIT" true (36 s). The injective query
     (`InitDone ==> inj-event RespAccept`) had not finished after several minutes; stopped for the laptop close.
   - The runner now does one query per ProVerif run, one run at a time (`PROVERIF_JOBS`, default 1;
     `PROVERIF_TIMEOUT`, default 1800 s), and prints each result as it finishes. A full run with 2 jobs was
     stopped by Claude Code for low memory on 2026-10-17 (free RAM was 0.4-0.7 GB); nothing was saved. Rerun
     only when the user agrees and memory allows: `python run_proverif.py > log.txt` in `tunnel\formal`.
   - Next: run it, then write `tunnel\formal\FORMAL_MODEL.md` with the results.
   - Expected finding to confirm: `pq_fs` (X25519 broken now, long-term keys stolen later) breaks secrecy, because
     both ML-KEM encapsulations go to static keys: no post-quantum forward secrecy. Answer to AUDIT_SCOPE question 4.
   - **Spec mismatch found:** `AUDIT_SCOPE.md` section 2 step 5 says the responder mixes `PSK_peer` into `ck` in
     RESP; the code (`make_response`, `consume_response`) mixes `E_r` instead, and only when a PSK is set. Fix the
     doc (and ask the user before changing code, since that changes the wire key schedule).
2. **GitHub.** Git and GitHub CLI installed with winget (open a new shell so they are on PATH). The user chose:
   public repo `ioessa-VPN`, MIT license. `.gitignore` written (caches, the audit package, keys and state).
   Still needed: the user runs `! gh auth login`, and gives the copyright name for `LICENSE`. Then `git init`,
   commit as the user's GitHub identity, `gh repo create ioessa-VPN --public --source . --push`. Then enable private vulnerability reporting (`SECURITY.md`).
3. **Book quotes: done 2026-10-18.** Every direct quote from the books, the SANS course and the WireGuard paper
   is paraphrased, with the line or page references kept, in ZERO_TRUST, SANS, OPERATIONS, NETWORK_SECURITY,
   SRE, KEY_LIFECYCLE, WIREGUARD_COMPARISON and SIDE_CHANNEL reviews. The OCR-error lists (which quoted
   garbled course text) became short notes. Quotes left are section titles and the project's own wording.
   The old `audit\` zip still has the quoted versions: keep it out of git, and rebuild it before sending.
4. **Real VPN.** The user chose: WireGuard for real traffic now, keep developing ioessa alongside. Not started.
   Needs a server: ask whether the user has a VPS or wants a WireGuard-capable VPN provider. Note for them:
   Rosenpass (post-quantum add-on) does not run on Windows clients, as far as known; check before promising it.

- **Core split (`tunnel\SPLIT_PLAN.md`).** Done 2026-10-17, shim removed: every file imports from
  the `vpn_*` modules. In tests, patch a name in the module that looks it up (for example `vpn_node.make_response`).
- **Real Windows TUN test: passed 2026-10-17** (elevated, `python tun_windows.py --selftest`: adapter created,
  session started, closed, no adapter left). Not yet tested: traffic through the adapter (needs addresses and routes).
- **IPv6 guard: run 2026-10-17** (elevated). `-Enable` adds one rule with the four ranges, is idempotent, keeps
  `::1` working; `-Disable` removes it. It was left disabled, because enabled it blocks outbound IPv6 for the whole PC.
  Not shown: that it blocks real traffic, since this network has no IPv6 internet (a ping to a public IPv6 address
  failed with or without the rule). Re-check on a network with IPv6.
- **Disclosure policy (`SECURITY.md`)**: written 2026-10-17. Reports go through GitHub private vulnerability
  reporting (the user's choice; no email address). The project is not on GitHub yet: once it is, the user must
  turn on Settings > Security > Private vulnerability reporting, or the link in `SECURITY.md` leads nowhere.
  The 7-day acknowledgement and 90-day disclosure are defaults I chose; change them if the user asks.
- **External audit** is not done. The package is ready (2026-10-17): `audit\AUDIT_REQUEST.md` (quote request
  and firm list), `audit\ioessa-tunnel-audit-2026-10-17.zip` and `audit\MANIFEST.sha256` (56 files; the
  unpacked zip passes 287 tests). The user sends the requests. Rebuild the package if `tunnel\` changes.
- **Freshness window, bandwidth numbers and key-age limits** are defaults that the user set or accepted.
  Revisit them only if asked.

## 5. Not verified

- Linux TUN (`tun_linux.py`) has never run on a kernel. Only its unit tests run.
- Windows TUN (`tun_windows.py`): adapter create and close tested for real; packet flow only with a fake DLL.
- `ipv6_guard.ps1`: rule add and remove tested for real; the blocking effect not observed (no IPv6 internet here).
- Real network paths, NAT, real-clock timers, official test vectors (none were found).
- OCR of the SEC401 slides is done, but the combined text is only in the scratchpad (see section 7).

## 6. Other sessions

- **ioessa-vpn-87** (idle at last check) wrote `tunnel\peer_reload.py` and `tunnel\test_reload.py`. Its
  runtime peer revocation works. Tell it before changing `load_peer_entries` or the peer reload code.
  I made one small change in `peer_reload.py` (it now handles PSK changes) and told it
  in an earlier message.
- **malwarebytes-44** works on unrelated Malwarebytes logs. It is not reachable now. Ignore it.
- A `ListAgents` call shows the current sessions.

## 7. Environment

- Windows 11 (PowerShell 5.1). Commands that chain with `&&` do not work. Use `;`.
- Python 3.13 from the Microsoft Store. `cryptography` is installed for the user.
- **`pip install` hangs or fails in this environment.** Do not rely on it. `pyflakes` is not installed,
  so static analysis has not been run (OPEN_ISSUES item 60).
- **Not elevated.** Creating a Wintun adapter, or changing firewall rules, needs an admin shell.
- **Tesseract 5.4** is installed at `C:\Program Files\Tesseract-OCR\tesseract.exe`.
- **No `pdftoppm`, no PyMuPDF.** PDF text is extracted with pypdf, through a small script run with `python -I`.
  `-I` ignores the user site-packages, so the script adds the user site path itself.
- Scratchpad (session-specific, may be gone): `%LOCALAPPDATA%\Temp\claude\<project>\a02eb37b-6d9d-4a55-8418-a34e7b2ac22c\scratchpad`.
  It holds the extracted texts: `boyd_mathuria.txt`, `fuzzing.txt`, `model_checking.txt`, `winint.txt`,
  `winint2.txt`, `sans401.txt`, and `sans401_ocr_all.txt` (OCR, with `===` page markers).
- Source books are in `%USERPROFILE%\Downloads`. They are copyrighted: do not copy their text into the repository.
- A PowerShell `Set-Content -Encoding utf8` writes a BOM on Windows PowerShell 5.1. Python can't read a BOM in
  `exec` strings, so write scripts with `python -c` or with a plain `[System.IO.File]::WriteAllText`.

## 8. Working habits the user wants

- Short answers. Numbered lists when a decision is needed. Say what is not done, and why.
- Act on clear requests. Ask only for things only the user can give (contacts, approval for installs or
  admin actions, product decisions). Say when something needs a decision.
- Report test results with the actual count and the status line, not a summary.
- Do not add files or features that were not asked for. Keep docs that describe current behaviour accurate.
- When a file changed on disk after being read, use the current content. Do not revert other sessions' work.
