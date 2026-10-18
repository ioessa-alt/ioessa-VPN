# Operations review: ioessa tunnel prototype

Status: learning prototype. Not audited, tested on loopback only. Nothing in this review was applied to a
firewall or host. Read with `README.md`, `THREAT_MODEL.md` and `NETWORK_SECURITY_REVIEW.md`. Their content
is not repeated here.

Book: SANS SEC401 course book (Secure Anchor Consulting, 2017), read from the OCR file
`scratchpad/sans401_ocr.txt`. "OCR l. N" is a line in that file. "PDF p." is the `=== PAGE n ===` marker
before the line. "printed p." is the page number printed in the footer, where the OCR shows it. The course
text is summarized in my own words, not quoted; the references point to where each point is made.

## 1. Corrections to the brief

- Module 2 "VPS" is Virtual Private Storage, an object-storage encryption option for cloud data. It is
  not a virtual private server [OCR l. 1639-1643]. It does not bear on the tunnel.
- CDP appears in two places (corrected 2026-10-17 from the OCR text, extracted and checked against the
  course images). Module 3 covers CDP manipulation on switches (OCR l. 680-682). Module 5, on wireless,
  notes that CDP is not encrypted when IPsec or another encryption protocol is used (OCR l. 6798, p. 195).
  Both concern the local network, not the tunnel's own packets.
- IPsec appears in three places (OCR l. 4511, IPv6 borrows parts of IPsec; l. 5631, a tcpdump lab that
  mentions encrypted IPsec traffic; l. 6798, the CDP note above). The course does not
  describe IPsec operation. This project does not use IPsec.
- "Bridged" appears in two places. The bridged-network text in Module 2 is about virtual machines [OCR l.
  1288]. The bridging risk for this review is the VPN-plus-home-Wi-Fi passage in Module 5 [OCR l. 5392-5398].
- The book has no passage on tunnel endpoints. Its VPN material is about VPN servers in general (section 4).

## 2. What the book says (summarized)

| Topic | Book point | Where |
|---|---|---|
| Router logging | Routers often log little, so most organizations cannot tell whether someone is attacking a router | OCR l. 3079-3083 (PDF p. 106, printed 103) |
| VPN in front of admin access | Best is to expose no ports to the Internet at all. Put a VPN server on a DMZ behind the router. VPN servers usually keep logs and routers usually do not, so funnelling all access through a VPN server that is logged and monitored makes an attack more likely to be noticed | OCR l. 3140-3149 (PDF p. 108, printed 105) |
| Router checklist | Change the default password; disable IP directed broadcasts; disable HTTP configuration; block ICMP ping requests; disable IP source routing; set ingress and egress address filtering; physical security; read the security logs | OCR l. 2926-2931, 2938-2948 |
| Router auth | Use certificates or pre-shared keys for SSH, not passwords | OCR l. 3114 |
| DMZ rules | Everything reachable from the Internet belongs in the DMZ and must hold no sensitive data. Systems with sensitive data stay private. DMZ to private only through a proxy | OCR l. 808-813 (PDF p. 33) |
| Firewall placement | Place the firewall where it can check that outbound traffic is legitimate, and control inbound traffic. A border router can drop packets whose source address is impossible | OCR l. 831-833, 853-857 |
| Filtering | Default deny: the firewall drops whatever is not needed | OCR l. 3285 |
| Defense in depth | Layers are needed because software has bugs, people misconfigure, and hardware fails | OCR l. 846-847 |
| VPN over home Wi-Fi | A machine on a corporate VPN and a home wireless network at once lets an attacker who compromises it ride the VPN into the corporate network | OCR l. 5397-5398 (printed 186) |
| Untrusted networks | Laptops join many untrusted networks and are likely to pick up malware. NAC can hold a system on an isolated VLAN until it has been scanned and patched | OCR l. 3206-3210 (PDF p. 110) |
| Hotspots | Public hotspots cannot demand 802.1X on clients. Users should be taught never to enter credentials over plain HTTP, since a hotspot can be faked | OCR l. 5644-5647, 5836-5842 (5836-5842 on printed p. 201) |
| Rogue APs | Run wireless intrusion detection to watch for rogue access points all the time | OCR l. 5776-5777 |
| Defense layers (wireless) | Firewalls and intrusion detection between the wireless and wired networks, plus personal firewalls on wireless clients | OCR l. 5455-5458 |
| Flow records | NetFlow-style records collect information about IP traffic for monitoring | OCR l. 717-718 |
| UDP | UDP suits traffic where some loss or reordering is acceptable. Syslog is listed as a UDP use | OCR l. 4345, 4351 (PDF p. 150) |

## 3. Logging and monitoring of the endpoint

### 3.1 What the code prints (read, not run except section 3.3)

Read: `vpn_server.py` (`serve`, `serve_tun`, `main`), `vpn_client.py` (`handshake`, `send_inner`, `run_tun`,
`main`), `vpn_core.py` (`Node.handle`, `_on_init`, `_on_resp`, `_on_cookie`, `_on_data`, `describe`, the key
loaders) and `vpn_keygen.py`. Every printed line is a fixed CLI string, an `Action.events` string from
`Node`, or `describe()` output.

| Event | Printed? | Text | Where |
|---|---|---|---|
| Server listening | yes | `vpn_server listening on ...` | server `main` |
| Handshake accepted (server) | yes | `handshake from {src} accepted; response sent, waiting for first data` | `_on_init` |
| Tunnel up (client; also after each rekey) | yes | `tunnel up with {src}`; CLI line `tunnel up: local index ..., remote index ...` | `_on_resp`, client `main` |
| Handshake failure | yes, generic | `handshake from {src} rejected: handshake failed` | `_on_init`, `_on_resp` |
| Bad mac1; bad mac2 without load | no | silent by design (V-C) | `_on_init` |
| Cookie reply (server, under load) | yes | `under load: cookie reply to {src}` | `_on_init` |
| Cookie stored (client) | yes | `cookie from {src} stored` | `_on_cookie` |
| Rejected data packet | yes, per datagram (printed lines share a budget since the SRE pass: `LOG_BURST` 20, `LOG_RATE` 5/s; the counter still counts every refusal; see SRE_REVIEW section 0) | `dropped packet from {src}: {reason}`. Reasons are fixed: bad size, counter too large, seq zero, out of window, replay, auth failed, bad trailer, bad padding, unknown index, source not allowed | `_on_data`, `ReplayWindow.check` |
| Roaming | yes | `roaming: endpoint {old} -> {new}` | `_set_endpoint` |
| Rekey start | no | none | `Node.initiate` |
| Session expiry | no | none | `Node._expire` |
| Timestamps | no | none on any line | all |
| Decrypted packet, queue mode | yes, metadata | `<- decrypted src -> dst proto= len=` | `serve`, client `main` |
| Outbound packet, client TUN mode | yes, metadata, per packet | `-> encrypted src -> dst ...` | `send_inner` |
| Shutdown counter (added in this review) | server only | `rejected inbound datagrams this run: N` | `RejectCounter` |

Notes:

- A flood of datagrams with an unknown receiver index prints one line each. Log volume follows attacker
  traffic. Nothing limits printing (THREAT_MODEL P-D3, U-D1).
- Silent drops (bad mac1, and bad mac2 without load) print nothing. That is correct on the wire, where it
  avoids an oracle. Locally, these are the largest class of hostile traffic, and nothing counts them.
- Handshake failures carry no reason. An unknown key, a stale timestamp and a bad AEAD print the same line.
  An operator cannot tell a wrong peer key from an attack. Check the key fingerprints (README) first.
- Rekeys: a completed rekey shows up as an extra `handshake ... accepted` (server) or `tunnel up` (client)
  line. The start of a rekey is not logged.

### 3.2 What is never printed (checked)

- Private keys, peer public keys, PSK, ephemeral and chaining keys: none is printed. Key loader errors name
  the setting, never the value (`vpn_core.py` 284-338, for example `private key must decode to 32 bytes`).
  The state dataclasses in `vpn_core.py` (lines 348-364 and 481-482) use `repr=False` on key fields.
- Plaintext payload: printed only by `describe(pkt, show_payload=True)`. `show_payload` is set only by
  `--show-payload`, which is off by default (server and client `main`). TUN mode (`serve_tun`, `run_tun`)
  never prints a payload, even with the flag.
- Exception: `vpn_keygen.py` prints the private key to stdout when run without `--out` (line 28). The
  help text says so. The key then reaches terminal scrollback, shell capture or CI logs. Use `--out` for
  real keys.

Test added: `OperationsOutputTests.test_payload_printed_only_with_show_payload`. It runs `serve()` with and
without `show_payload` and checks the printed lines. Mutation check, in a scratch copy where `describe()`
always adds the payload: the test failed, with `payload=b'SECRET-PAYLOAD-123'` in the output line.

### 3.3 Run check

`vpn_server.py --port 45599 --idle-timeout 3` with generated keys, then three datagrams with an unknown
index sent to it. Output:

```
vpn_server listening on 127.0.0.1:45599 (1 peer(s))
dropped packet from ('127.0.0.1', 60100): unknown index
dropped packet from ('127.0.0.1', 60100): unknown index
dropped packet from ('127.0.0.1', 60100): unknown index
rejected inbound datagrams this run: 3
```

The counter line works. The per-datagram lines appear as the datagrams arrive. There are no timestamps.

### 3.4 Logging practice for an operator

- Keep: the event type, the peer address and port, the fixed reason strings, the shutdown counter. Add time
  and a peer label outside the program. Pipe stdout through a timestamping tool, because the program prints
  no time.
- Do not keep: `--show-payload` output (plaintext). In production, avoid the per-packet `<-` and `->` lines
  in queue mode and the client's TUN mode. They record destination addresses and sizes of every packet,
  which is traffic metadata. The book's Net Flow description [OCR l. 717-718] points to summary records
  instead.
- Storage: stdout only. There is no log file or rotation. If stdout goes to a file, the volume of
  unknown-index lines is set by the attacker. Cap it with an external tool. **Stale in part:** printed refusal
  lines are now limited by a shared budget in code (`Node._refuse`, test `test_refusal_log_is_rate_limited_but_still_counted`,
  test_vpn.py). The file itself is still not capped in code.
- Off-host: the book describes UDP as the transport for loss-tolerant traffic [OCR l. 4351]. Send logs over
  a reliable path, or accept and count the loss.

## 4. Placement relative to the firewall

Book model: systems visible from the Internet go to the DMZ, and systems with sensitive data stay private.
The only DMZ-to-private path is a proxy [OCR l. 808-813]. The firewall sits where the traffic paths cross,
with a border router in front of it [OCR l. 829-833, 853-857].

Applied to the tunnel:

1. The server is visible from the Internet, so under the book's first rule it belongs in the DMZ, not on the
   private LAN. Its only inbound exposure should be the one UDP port (`--port`). Set `--bind` to the public
   address, not 0.0.0.0 (README table).
2. Tension with rule 1: the server holds a private key, and the rule says Internet-visible systems must hold
   no sensitive data. A tunnel endpoint cannot avoid holding its key. Practical answer: a
   single-purpose gateway, with the key file readable only by the service account (Linux). On Windows the
   file mode is ignored (THREAT_MODEL K-I3). The book does not discuss this case. This is an analysis of
   its rule, not a book statement.
3. The book prefers exposing no ports to the Internet [OCR l. 3141-3142] and puts the VPN behind the
   firewall, so administrators reach internal ports only after logging in. A WireGuard-style endpoint is
   itself the open UDP port, so the preference cannot be fully met. Compensation: restrict the port to known
   client IPs (README rule 1), keep it closed otherwise, and log drops and accepts (section 3).
4. The tunnel's inside is not a trusted zone. Traffic from `10.8.0.0/24` should reach internal hosts only
   through firewall rules, following the book's default deny at the firewall [OCR l. 3285]. Do not
   route the tunnel prefix into the private LAN without a FORWARD rule.
5. Defense in depth [OCR l. 846-847] supports a firewall on the endpoint host as well as at the edge. The
   README rules apply on the endpoint.

The README iptables examples were not applied or run.

## 5. Router and firewall hardening

Book checklist [OCR l. 2926-2931, 2938-2948], mapped to a Linux gateway running this program:

| Book item | Prototype | Status |
|---|---|---|
| Change default password | No password login. The program uses keys only, and the book prefers keys to passwords for SSH [OCR l. 3114] | Matches design |
| Block ICMP ping requests | README rule 3 allows echo-request on `ioessa0` only | Partly. Check the public interface |
| Disable IP source routing | Not in README. Check `net.ipv4.conf.*.accept_source_route` | Not checked |
| Disable IP directed broadcasts | Not in README. Check `net.ipv4.icmp_echo_ignore_broadcasts` | Not checked |
| Disable HTTP configuration | No HTTP service | Not applicable |
| Ingress and egress filtering | README rule 1 (default drop) and rule 2 (anti-spoof). No egress rule in README | Partly |
| Border router source filter | Upstream device, not this host. Drop RFC 1918 sources arriving from outside [OCR l. 854-857] | Not checked |
| Physical security | Out of scope | Not checked |
| Review the logs | Section 3. The book notes routers rarely log [OCR l. 3082-3083] | Open |

`ip_forward` is covered in section 7.

## 6. Client on an untrusted network

Book points: a laptop on untrusted networks can pick up malware and infect trusted hosts. Use NAC or
isolation until it is scanned and patched [OCR l. 3206-3210]. The VPN-over-home-Wi-Fi path is the attack
[OCR l. 5397-5398]. Hotspots invite masquerading portals [OCR l. 5644-5647, 5836-5842]. Use layers:
distributed firewalls, personal firewalls on wireless clients, IDS [OCR l. 5455-5458].

Effects on this prototype:

1. Pinned keys stop a hotspot impostor from completing the handshake (THREAT_MODEL H-S1). The client then
   prints only `error: no handshake response from the server (check the port and both public keys)`
   (client `main`). A captive portal, a blocked UDP port and a wrong key look the same. This is expected
   behaviour. It is not tested on a real network.
2. Split tunnel: the default `--protect` routes only `10.8.0.0/24`, and BYPASS sends the rest out directly.
   Other hosts on the hostile Wi-Fi still reach the client machine. The book's personal-firewall advice
   applies.
3. Client firewall: the README gives the client only outbound UDP to the server port and the ICMP rule. Add
   a rule that allows nothing else outbound to the server network, and nothing inbound except replies.
4. Key file: on Windows the file mode is ignored (THREAT_MODEL K-I3). Keep the key where only the user can
   read it.
5. Operating rule for this prototype: do not run a client on untrusted Wi-Fi without a host firewall. There
   is no posture check, so NAC is a gap (section 9).

## 7. Bridging: a VPN-connected host joins two networks

Book warning [OCR l. 5397-5398, quoted in section 2]. In this prototype:

- A client with the tunnel up and a LAN connection is dual-homed. The tunnel adds a route. Routes alone do
  not forward traffic, so the host becomes a bridge only if forwarding or NAT is enabled.
- Forwarding is off by default. README rule 5 says forwarding is needed only when the endpoint carries
  traffic to other networks. The code does not check `net.ipv4.ip_forward`. The operator must check it.
- Cryptokey routing limits what a peer can send. In TUN mode, inner sources must fall in the tunnel routes
  (`allowed_ips`, set in the server and client `main`). A peer holding its key cannot send packets with
  LAN sources through the server. The queue demo is permissive by default (THREAT_MODEL D-S1).
- IPv6 is a second path. The host may send IPv6 outside the tunnel (THREAT_MODEL section 6, "Open").
- Recommendation: on clients, forwarding off and no NAT of tunnel traffic. While the tunnel is up, disable
  or firewall IPv6 on the physical NIC. On the server, add FORWARD rules only for named destinations.

## 8. Operations checklist

1. Use a dedicated gateway for the server, with no other services. Make the key file readable only by the
   service account.
2. Set `--bind` to the public address, open one UDP port, and restrict it to known client IPs (README rule
   1). Add the anti-spoof rule (rule 2).
3. Do not use `--show-payload` outside a lab. Use `--use-psk` only with a random PSK (THREAT_MODEL H-S2).
4. Capture server stdout and timestamp it outside the program. Watch the rate of `unknown index` lines while
   the server runs. Read the `rejected inbound datagrams this run` line on shutdown.
5. Check each peer's public key fingerprint over a second channel (README).
6. Turn forwarding off on endpoints. Do not route LAN prefixes into the tunnel.
7. On clients, allow outbound traffic to the server only. Do not run a client on untrusted Wi-Fi without the
   controls in section 6.
8. Rekeys happen automatically after 120 s of use or at the message limit. There is no rotation procedure
   beyond replacing keys by hand.

## 9. Gaps

- No timestamps, no log levels, no log file.
- Rekey starts are not logged. Silent drops are not counted.
- **Stale, corrected:** an unknown-index flood no longer prints one line per datagram. A shared budget bounds the printed lines (`Node._refuse`, `LOG_BURST` 20, `LOG_RATE` 5/s). There is still no per-source limit (THREAT_MODEL U-D1).
- The rejection counter is on the server only. The client has none.
- `vpn_keygen.py` prints the private key when `--out` is not given.
- Ctrl+C on the server ends with a traceback (the client prints `stopped`). Read from the code, not run.
  Not changed.
- THREAT_MODEL P-D1 says "Each failure is caught and logged". Inside `Node`, only `HandshakeError` and
  `ESPError` are caught. Any other exception would end `serve()`. The malformed-input tests cover the inputs
  tried. Not fuzzed.
- The firewall rules, the sysctl checks and the Linux TUN have not been run on a host.
- There is no NAC or posture check.
- The book's VPN and firewall text is high level. This review does not claim more than it says.

## 10. Test results

Command, from `tunnel\`: `python -m unittest`. Before the changes: `Ran 120 tests ... OK`. After the first
pass (3 new tests in `OperationsOutputTests`): `Ran 123 tests`. Current count, after the second pass
(13 new tests in `test_hardening.py`, and the state and other suites): 170 tests.

```
Ran 170 tests in 15.908s

OK
```

Current count (finalization pass): `Ran 179 tests in 15.744s`, `OK`.

The new leak test also failed against the mutated scratch copy described in section 3.2.

## 11. Notes on the OCR source

- The course text is summarized, not quoted, so OCR misreadings do not reach this document. Some lines
  are garbled in the OCR (for example around l. 3125 and l. 3285); the summaries rely on the clean
  passages nearby.
- OCR l. 840: the footer reads "30" on a page that is probably 31. Section 2 cites PDF page numbers for that
  area instead.
- Printed page numbers for PDF p. 106, 108 and 110 come from footers near OCR l. 3085, 3156 and 3205. Treat
  them as possibly off by one.
- The OCR text was not checked against the printed book. All quotes were read in the OCR file.
