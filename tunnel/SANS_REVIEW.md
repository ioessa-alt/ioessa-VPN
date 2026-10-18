# SANS SEC401.1 review of the ioessa tunnel prototype

Source: SANS SEC401.1 *Network Security Essentials* courseware, version C02_02, Secure Anchor Consulting, 2017,
read from the OCR text `scratchpad\sans401_ocr.txt`. "OCR l. N" is a line in that file. The course is summarized
in my own words, not quoted; each point gives the line where the course makes it. Scope: the tunnel code (`vpn_core.py`, `vpn_server.py`, `vpn_client.py`, `tun_linux.py`, `analysis/analyze.py`)
and the four existing review documents. This file does not repeat their STRIDE tables. Status key: **Met** = covered in code or docs and checked. **Partly** = covered, with a gap stated. **Not met** =
absent. **N/A** = does not apply.

## 1. Summary

- This file reviews the SANS course only. The OCR text has no ESP format, no SA or SPI material, no IKE, no
  anti-replay window, and no default-discard rule stated as such. Its VPN material is a few paragraphs (OCR l. 3141-3149).
  NETWORK_SECURITY_REVIEW.md and README.md:161 cite a different book, Stallings's *Network Security Essentials*
  (extracted text: scratchpad\nse_stallings.txt). Both phrases they rely on are in it, at lines 18466 and 18644.
  Those citations are not affected by the SANS course and stay as they are.
- The most serious code finding is in no document: with more than one client, TUN routing is wrong (finding 1).
- The course's detection argument depends on logging at the VPN endpoint (OCR l. 3147-3149). The tunnel logs
  little that a monitoring team could use (finding 3).

## 2. Findings, ranked

1. **Partly met (blocked at startup, not solved): TUN cryptokey routing with more than one peer.** In TUN mode every
   peer's `allowed_ips` is set to the same routes, default `10.8.0.0/24` (`vpn_server.py:235-236`). The server now
   refuses to start when two peers would share routes (`vpn_server.py:237-243`, `check_allowed_ips_disjoint`), so the
   overlap below cannot occur in a running server. Per-peer routes are still missing. The original finding was written
   against older code. Outbound, `_pick_peer` (`vpn_server.py:107-116`,
   called at line 162) returns the first peer in insertion order (`vpn_core.py:766, 785`) whose `allowed_ips`
   contain the destination. Inbound, `_source_allowed` (`vpn_core.py:1054-1055`) accepts any source in the /24 from
   any peer. From code reading, not run: (a) a packet for client B can be encrypted for client A; (b) one
   authenticated client can send with another client's or the server's tunnel address. README.md:143-145 says each
   side "accepts and sends only the tunnel prefix". That holds only with one peer. The course's least-privilege rule:
   give each entity only the access its job needs (OCR l. 782-783). I found no test with two
   TUN peers. Fix: reject overlapping `allowed_ips` at startup, add a per-peer route option, and add a two-peer test.

2. **Partly: a compromised, authenticated client is not in the threat model.** The course warns that attackers go
   after weak clients to get into established VPN tunnels and, through them, internal networks (OCR l. 5487-5488). It
   also names a VPN client on home Wi-Fi as the attack path (OCR l. 5397-5398). THREAT_MODEL.md covers local
   processes (P-T1, K-I2) and forged peers, but has no row for an infected host that holds a valid key. The course's
   answer is isolation until scanned: Network Access Control can keep a system on an isolated VLAN until it has been
   scanned and patched (OCR l. 3209-3210). The tunnel has no posture check
   (OPERATIONS_REVIEW.md section 9). Fix: add the threat row, and recommend a /32 route per client.

3. **Partly: logging is too thin for the course's detection argument.** The course notes that VPN servers usually keep
   logs while routers usually do not, so routing access through the VPN makes an attack more likely to be seen
   (OCR l. 3147-3149), and it treats detection as mandatory (OCR l. 3211). Encrypted sessions are largely hidden from
   intrusion detection that inspects session contents (OCR l. 6350-6351). So the endpoint log is the only detection
   point. The code has no log file, no timestamps, and no line for a rekey start or a session expiry. Its shutdown
   counter (`vpn_server.py:226, 235`) also adds `node.refusals_unlogged`, so some silent refusals are counted.
   OPERATIONS_REVIEW.md section 3 lists the same gaps. This review treats them as required before real use.

4. **Corrected: the Stallings citations were checked against the right book.** This review first treated the Stallings
   citations as unsupported, because it compared them to the SANS OCR. That was a mistake. NETWORK_SECURITY_REVIEW.md
   and README.md:161 cite Stallings's *Network Security Essentials*, which is in the downloads and was extracted to
   scratchpad\nse_stallings.txt. The phrases are there. The course's own equivalents, for comparison:
   - default deny: the firewall drops whatever traffic is not needed (OCR l. 3285);
   - border filter: drop inbound packets with impossible sources, such as RFC 1918 private addresses (OCR l. 854-856).
   No change needed to the Stallings citations. The ESP claims in NETWORK_SECURITY_REVIEW.md are checked against
   Stallings's text, not against this course.

5. **Partly: README says ICMP fragmentation-needed is "not from the book".** The course lists the ICMP type for
   fragmentation needed with the DF flag set (OCR l. 3982), and explains that an ICMP error carries the whole IP
   header of the offending packet plus the first 8 bytes of its payload (OCR l. 4028-4031). It does not discuss
   path MTU. README rule 4 fits that description. Cite those lines instead of "general practice".

6. **Partly: OPERATIONS_REVIEW.md section 1 has two wrong corrections.**
   - CDP is not "only in Module 3". It is also in Module 5, in the wireless section, which points out that CDP stays
     unencrypted even when IPsec or another network-layer encryption is in use (OCR l. 5569-5571). That bears on this
     tunnel: network-layer encryption does not cover every leak.
   - The IPsec mentions are not only the tcpdump lab (OCR l. 4622). OCR l. 3765 (IPv6 borrows IPsec for endpoint
     authentication and packet encryption) and l. 5570 also mention it.
     The conclusion stands (the course does not explain IPsec), but the list is incomplete.

7. **Partly (low): the analyzer's minimum length does not match the wire.** An empty inner datagram (keepalive) gets
   2 bytes of padding (`pad = (-(len(inner) + 2)) % 4`, `vpn_core.py:615`). On the wire it is 16 + 2 + 2 + 16 = 36
   bytes. `analysis/analyze.py:42` sets `DATA_MIN_LEN = 16 + 16 + 2` (34), with a comment that counts no padding. It is
   a lower bound, so valid packets are not rejected, but the value and comment are wrong.

8. **Partly: the tunnel is an open UDP port, which the course tries to avoid.** The course's first choice is to expose
   no ports to the Internet at all (OCR l. 3141-3142). Its answer is a VPN in a DMZ behind the router (OCR l. 3143-3146).
   The tunnel is that VPN, so one open port is a design fact (OPERATIONS_REVIEW.md section 4). Mitigate by restricting
   the port to known client addresses (README rule 1).

9. **Not met: no integrity or age check on the replay state file.** The course describes a file-integrity checker that
   raises an alert when files appear, change or disappear against its rules (OCR l. 6787-6788).
   Replay protection after a restart depends on the state file being the latest copy (THREAT_MODEL.md section 7). The
   tunnel does not check it. Fix: an operator integrity check, and a start-up line that prints the file's path, size
   and mtime.

## 3. Topic table

**A. VPN and IPsec**

| Course point | Tunnel | Status |
|---|---|---|
| VPN server behind the router, in a DMZ, fully logged (3141-3149) | Tunnel is the VPN endpoint. Placement is an operator step (OPERATIONS_REVIEW s.4) | Partly |
| IPv6 incorporates IPsec (3765) | IPv4 only inside the tunnel; the host may send IPv6 outside it (README:145) | Partly (known open) |
| Encrypt as low in the OSI stack as possible (5567-5571) | Outer UDP ports, receiver index, 64-bit counter and sizes are clear (THREAT_MODEL U-I1) | Partly (accepted, documented) |
| Least access needed (782-783) | Per-peer `allowed_ips`; TUN mode gives every peer the same /24 (`vpn_server.py:223-225`) | Not met for 2+ peers; met for one |
| Keys over passwords: use certificates or pre-shared keys (3114) | Keys only, no password login (README "Keys") | Met |

**B. Firewall and DMZ**

| Course point | Tunnel | Status |
|---|---|---|
| Internet-visible systems in the DMZ, without sensitive data; DMZ to private only via a proxy (807-813) | Server is public and holds a private key; no proxy. OPERATIONS_REVIEW s.4 items 1-2 | Partly. Course does not address a key-holding gateway |
| Firewalls between networks and between zones of different trust (777-780); at path intersections (843-844) | Endpoint firewall rules are documentation only (README "Firewall and network setup") | Partly (not applied) |
| Border filter blocks RFC 1918 sources from outside (853-856) | README rule 2 drops tunnel-prefix sources on the public interface | Met in purpose. Re-cite (finding 4) |
| Default deny at the firewall (3285) | README rule 1 drops inbound by default | Met. Re-cite (finding 4) |
| Defense in depth, because software has bugs and people misconfigure (846-847) | Endpoint firewall plus server checks (OPERATIONS_REVIEW s.4 item 5) | Met (documented) |
| Source routing can be used to get around firewalls and other defenses (2985-2989) | Not in README. Inner IP options are not checked (`is_ipv4` checks version only) | Not checked |

**C. Untrusted networks and wireless**

| Course point | Tunnel | Status |
|---|---|---|
| Laptop on untrusted networks gets infected; NAC isolates until patched (3206-3210) | No posture check; client guidance only (OPERATIONS_REVIEW s.6) | Not met |
| Home Wi-Fi plus corporate VPN gives an attacker access (5392-5398) | Not modelled in THREAT_MODEL (finding 2) | Partly |
| A segregated VPN can still be reached through weak clients (5485-5488) | Same gap as finding 2 | Partly |
| Hotspot masquerading; mutual authentication seen as hard to do in practice (5644-5649, 5836-5842) | Pinned keys: an impostor cannot complete the handshake (THREAT_MODEL H-S1). Error text is generic | Met (not tested on a real network) |
| Firewalls and IDS between wireless and wired networks, personal firewalls on wireless clients (5455-5458) | Client host firewall advised, not required (OPERATIONS_REVIEW s.6 item 3) | Partly |
| WEP and WPA (5163-5338); rogue AP detection (5776-5777) | No Wi-Fi security in the tunnel | N/A |

**D. TLS**

| Course point | Tunnel | Status |
|---|---|---|
| SSL as an encrypted tunnel; server identity; integrity (6310-6320) | AEAD for confidentiality and integrity; pinned keys for identity | Met in purpose. No CA (different trust model) |
| The certificate name must match the domain exactly (6317-6319) | Fingerprint over a second channel (README "Keys") | Met (manual) |
| Server presents a public-key certificate (6330-6331) | No certificates, by design (README "Keys") | Partly (explained) |
| Claims a new key for every request (6341-6342) | Rekey every 120 s or at the message limit (THREAT_MODEL H-X7) | Course is loose. Do not copy |
| Encryption hides actions from intrusion detection (6350-6351) | Logging must be at the endpoint (finding 3) | Partly |
| SSL should not make you feel safer than you are (6304-6305) | THREAT_MODEL s.7 lists what the tunnel does not stop | Met |

**E. Logging and monitoring**

| Course point | Tunnel | Status |
|---|---|---|
| Routers log poorly (3082-3083); read the security logs (2931) | Per-datagram lines, no timestamps, no log file (OPERATIONS_REVIEW s.3) | Partly |
| Syslog is a UDP use; UDP suits traffic that can lose packets (4345, 4351) | Logs go to stdout; no transport defined (OPERATIONS_REVIEW s.3.4) | Partly |
| NetFlow gives summaries of traffic (717-720) | Client TUN mode prints a metadata line per packet (`vpn_client.py:238`) | Not met (operator told to avoid) |
| File-integrity checker alerts on changes (6785-6788) | None on the state file (finding 9) | Not met |

**F. Packet analysis and wire format**

| Course point | Tunnel | Status |
|---|---|---|
| IP header bytes are numbered from 0 (3793-3794) | "Byte 0 is the message type" (README:224; `vpn_core.py:46`) | Met |
| The UDP checksum catches transmission errors; it is not a security control (4406-4410) | Integrity comes from the AEAD, not the UDP checksum (THREAT_MODEL U-T1) | Met |
| ICMP fragmentation needed with DF set (3982); error carries IP header and 8 bytes (4028-4031) | README rule 4 (finding 5) | Met |
| ICMP code 9 means a router or firewall rule blocked the traffic (4022-4023) | README rule 1 drops silently, so a probe gets no reply | Met (silence is a choice the course does not discuss) |
| Analyzer minimum for an empty DATA message | `analysis/analyze.py:42` (finding 7) | Partly |

**G. Router hardening, applied to the endpoint host**

| Course point | Tunnel | Status |
|---|---|---|
| Hardening list: default password, directed broadcasts, HTTP, ICMP, source routing, filters, logs (2922-2931) | Keys, no HTTP service, ICMP echo on `ioessa0` only. Broadcast and source-route settings absent (OPERATIONS_REVIEW s.5) | Partly |

## 4. Where the tunnel docs get the course wrong, or overstate

- Stallings citations and phrases (finding 4): NETWORK_SECURITY_REVIEW.md, README.md:161-164.
- "Not from the book" for ICMP fragmentation (finding 5): README.md:169-170.
- OPERATIONS_REVIEW.md section 1 corrections (finding 6).
- README.md:143-145 overstates cryptokey routing for more than one peer (finding 1).
- Test counts disagree: README 140 (line 231), NETWORK_SECURITY_REVIEW 120 (section 7), OPERATIONS_REVIEW 123
  (section 10). The suite was not run here, because another agent is editing `tunnel\`.

## 5. What the course changes in the recommendations

1. Per-peer routes come before a second client. The least-access rule applies to each peer (finding 1). This is a code fix.
2. Logging moves from "nice to have" to "required before real use", because the course's detection argument needs the
   endpoint log and encryption hides traffic from network IDS (finding 3).
3. Keep the firewall rules. Change their citations to OCR l. 854-856 and l. 3285 (finding 4).
4. The course's isolation principle (OCR l. 3209-3210) makes a client host firewall a condition on untrusted networks.
5. Add an operator file-integrity check on the state file to OPERATIONS_REVIEW.md (finding 9).

## 6. Notes on the OCR source

- The course is summarized, not quoted, so OCR misreadings do not carry into this file. Where a line is garbled in
  the OCR (for example l. 3125 and l. 3285), the summary relies on the clean text nearby.
- `=== PAGE n ===` markers are PDF pages. Printed page numbers from footers may be off by one (OPERATIONS_REVIEW.md section 11).

## 7. Limits

- OCR only, not checked against the printed book.
- Stallings is not in the source, so NETWORK_SECURITY_REVIEW.md's Stallings claims could not be checked.
- Finding 1 is from code reading and was not run. The grep found no test with two TUN peers.
- Of `analysis\`, only `analyze.py:42` and `:114` were read. The test suite was not run.
- Written: this file only. No other file was changed; no `.py` file was edited.
