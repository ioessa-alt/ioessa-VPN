# Network security review against Stallings, *Network Security Essentials*

Scope: the tunnel prototype in this folder (`vpn_core.py`, `vpn_server.py`, `vpn_client.py`,
`tun_linux.py`, `vpn_keygen.py`, tests). The reference is the book, read from its extracted text.
Page numbers are the book's printed pages. This is a comparison for learning. It does not claim
interoperability with RFC 4301, 4303, 7296 or any other standard, and this design is not one of them.

Read before writing: `README.md`, `THREAT_MODEL.md`. This review does not repeat the STRIDE tables.

## 1. Chapter 9, IP Security: ESP framing and SA handling

What the book says (Sections 9.1, 9.3, 9.5):

- ESP packet fields: SPI (32 bits), Sequence Number (32 bits), Payload Data, Padding (0 to 255
  bytes), Pad Length (8 bits), Next Header (8 bits), and the ICV, which covers the whole ESP packet
  except the authentication data itself (p. 315). The ICV is computed after encryption (p. 316).
- Padding serves alignment: ESP needs Pad Length and Next Header to end on a 32-bit boundary (p. 316).
- Anti-replay: the first sequence number is 1. The sender must never let the sequence number wrap
  from 2^32 - 1 back to zero (p. 317). The receiver window default is W = 64 (p. 317).
  Inbound: a packet in the window is MAC-checked before its slot is marked; a packet to the left
  of the window, or one that fails authentication, is discarded (p. 317).
- SA: a logical connection in one direction only, so two-way traffic needs two SAs. The SA is
  identified by the destination address and the SPI. The receiving side picks the SPI, and it has
  local significance only (Section 9.1 for the SA definition; Section 9.2 for the SAD fields).
- Transport mode protects the payload; tunnel mode protects the entire inner IP packet, including
  its header (ESP in tunnel mode, Section 9.1).
- Key management: manual keying works for small setups that rarely change (p. 325).
  Automated keying is the other option (IKE, Section 9.5).

| Book (ESP) | This prototype | Result |
|---|---|---|
| SPI, 32 bits, chosen by the receiver | Receiver index, 4 bytes at offset 4, chosen by the receiver with `_new_index()`, unique among live sessions and pending handshakes | Match in role and size |
| Sequence number, 32 bits, first value 1 | 8-byte counter field at offset 8. Used as 32 bits only: `open_data` rejects counter > `SEQ_MAX` (2^32 - 1). Counter starts at 1 (`send_counter` is incremented before use) | Match in use. Field is wider than needed (ESN is not implemented) |
| Sender must not cycle the sequence number | Sending stops at 2^32 - 1024 and raises `RekeyRequired` (`REKEY_AFTER_MESSAGES`) | Match, with a stricter margin |
| Padding 0 to 255 bytes, Pad Length and Next Header right aligned in 32 bits | Pad to a multiple of 4 so that payload + pad + 2 is 4-byte aligned. Pad is 0 to 3 bytes. Checked: for all inner lengths 0 to 1400, the padded plaintext length is a multiple of 4 and round-trips | Match in alignment. Pad range is smaller (deliberate, see section 1.1) |
| Pad Length, 1 byte | Byte `pt[-2]`, checked against the plaintext length | Match |
| Next Header, 1 byte | Byte `pt[-1]`, must be 4 (IPv4-in-IP). Other values are rejected | Match for the one payload type used |
| ICV after encryption, covers the packet minus the ICV | 16-byte Poly1305 tag from ChaCha20-Poly1305. Covers the 16-byte data header (as associated data) and the ciphertext | Match in role and size. Tag and header are an AEAD, not a separate MAC |
| Anti-replay window W = 64, check before MAC, mark after | `ReplayWindow` with `WINDOW = 64`. `check()` is read-only, `update()` runs after AEAD verification | Match, and the book's order is followed |
| Tunnel mode encapsulates the whole inner IP packet | The inner IPv4 datagram is the payload, and the outer packet is UDP | Tunnel-mode shape. No transport mode |
| SA: one-way, two SAs for two-way traffic | One `Session` per handshake holds a send key and a receive key, with one local and one remote index | Same effect, different packaging. Deliberate |
| SA lifetime by time or by byte count | By time (120 s rekey, 180 s reject) and by message count. No byte-count lifetime | Partial. Byte lifetime is a gap (see section 4) |
| Manual keys practical for small static environments | Keys are configured by hand. See section 2 | Match with the book's own description |
| IKE for automated keying | Noise IK handshake (1 RTT, with cookies and a timestamp replay check) | Not IKE. Different design, not interoperable |

### 1.1 Deliberate differences (not bugs)

- **Not RFC 4303 ESP.** The type byte, the 3 reserved bytes, the 8-byte counter, the AEAD in place of
  a separate ICV, and the 0 to 3 byte pad are all this prototype's own design (see
  `THREAT_MODEL.md`, section 3). Packets from this code will not be accepted by an IPsec stack.
- **Padding content.** The code pads with bytes 1, 2, 3, ... The book text read here does not
  describe the pad content, so this review does not claim it matches the book or RFC 4303.
- **Receiver index instead of SPI plus destination address.** Lookup is by the local index alone.
  This works because one node holds all its sessions.
- **Counter width.** The field is 64 bits and accepted values are 32 bits. This keeps the book's
  2^32 - 1 limit and leaves room for ESN later. ESN is not implemented.
- **Pad length 0 to 3, no traffic-flow confidentiality padding.** The book describes extra padding
  as optional (p. 316). This prototype does not add it.

### 1.2 Where the code follows the paper's order (checked, unchanged)

On an authenticated packet, `_on_data` updates the endpoint before the reverse-path check (`_source_allowed`).
This is the WireGuard paper's order (authenticate, roam, then check AllowedIPs). It is not an
RFC ESP rule, so this review leaves it as is.

## 2. Chapter 4, Key distribution and user authentication: how keys reach each side

What the book says:

- The options for delivering a session key (4.2, p. 123): hand delivery, a third party delivering
  it, the old key encrypting the new one, or a KDC. The first two mean delivering the key by hand,
  which the book finds clumsy for end-to-end use across a network.
- Public-key certificates (4.4, p. 138): a public key that is simply announced can be forged by
  anyone. The fix is a certificate, a public key plus an identity signed by a trusted third party
  such as a CA.
- Plain Diffie-Hellman does not authenticate either party (4.4, p. 139).
- Four means of user authentication (4.1, p. 122): something you know, have, are, or do. Network
  authentication mostly uses cryptographic keys and passwords.
- Manual key management for IPsec suits small setups that rarely change (9.5, p. 325).

What the code does:

| Setting | How it reaches the side | Checked |
|---|---|---|
| This side's private key | `--key-file` or `IOESSA_VPN_PRIVATE_KEY_FILE`, or env `IOESSA_VPN_PRIVATE_KEY` (`load_static_private`) | Base64, 32 bytes. Value is not printed |
| Peer's public key(s) | `--peer-key-file` or env `IOESSA_VPN_PEER_PUBLIC_KEY`, comma or newline separated (`load_peer_publics`) | Base64, 32 bytes, not low order (`public_key_from_b64`) |
| Optional PSK | env `IOESSA_VPN_PSK`, only with `--use-psk` | At least 32 bytes, not all zeros |

Keys are never in source (`test_static_keys_are_not_in_source`). The server accepts only the keys
it was configured with, and the client accepts only the server key it was configured with.

**Decision.** Keep manual, out-of-band public keys. Do not build a PKI. Reasons:

1. The prototype has one server and a few clients, which is the book's small and rarely changing
   case (9.5). A CA adds a trust root, revocation and issuance code, which is far outside a prototype.
2. The book's concern in 4.4 is forgery of a public announcement. Here the key is not announced
   on a network. The operator copies it in by hand, so the trust anchor is the operator's own
   channel.
3. The handshake uses the configured static keys in the key agreement (Noise IK), so a wrong key
   fails the handshake. It does not silently create a session with the wrong peer.

**What was added.** A paragraph and a one-line command in `README.md` under "Keys". The operator
compares the SHA-256 of the 32 raw key bytes over a second channel. The command was run here and
prints a 64-character hex digest for a generated key.

**What would be needed for more peers.** Signed certificates from a CA, or a KDC-style service as
the book describes in 4.2. Neither is built, and neither is claimed.

## 3. Chapter 6, Transport-level security (TLS), for comparison

What the book says (TLS sections, Chapter 6):

- The Record Protocol gives confidentiality and message integrity. It keeps a separate client write
  key and server write key (the book's list of session state).
- "Each party maintains separate sequence numbers for transmitted and received messages ... Sequence
  numbers may not exceed 2^64 - 1" (TLS Record Protocol, session state).
- The Handshake Protocol lets client and server authenticate each other and negotiate algorithms
  and keys.
- X.509 certificates are used in SSL and TLS (4.4, p. 138).

Comparison:

| TLS | This prototype | Note |
|---|---|---|
| Separate write keys per direction | Separate send and receive keys (`_transport_keys`) | Match in idea |
| Per-direction sequence numbers, limit 2^64 - 1 | Per-session counter, limit 2^32 - 1024 | Stricter, same idea |
| Server authenticated by X.509 certificate | Responder authenticated by its pinned static key in the Noise IK handshake | Different trust model: no CA |
| Negotiation of algorithms | No negotiation: one fixed suite | Deliberate (THREAT_MODEL H-X5) |

The main difference is the trust model. TLS on the web relies on a CA hierarchy. This prototype
relies on the operator's pinned keys (section 2).

## 4. Chapter 12, Firewalls: packet filtering and the VPN endpoint

What the book says (Sections 12.2 and 12.3):

- A firewall is one point that all traffic must pass (p. 413). Design goal 1: all traffic passes through it.
- Packet-filter rules are based on source and destination IP, transport ports, the protocol field,
  and the interface (p. 414).
- Default policy: default discard (anything not explicitly allowed is blocked, p. 414), or default
  forward. The book calls default discard the more conservative choice.
- IP address spoofing countermeasure: drop any packet that arrives on an outside interface but
  claims an inside source address (p. 417).
- A host-based firewall is software that protects one machine (p. 421).

What the README said before this review: it covered the TUN routes and the default route refusal,
but gave no operator checklist for the UDP port, the tunnel prefix, the interface, the bind
address, or the spoofing rule. This was the gap.

What changed: `README.md` has a new section "Firewall and network setup (documentation only)". It
lists:

- the outer UDP port (`--port`, default 4500; examples 45500) and the allowed peer address,
- the tunnel prefix (10.8.0.0/24) and the TUN interface (`ioessa0`, or `veth-srv` in the namespace example),
- the bind address (`--bind`, not 0.0.0.0),
- a default-deny inbound rule, the anti-spoofing rule from the book, ICMP echo on the TUN interface,
  ICMP fragmentation-needed on the public path (general practice, not from the book), and what
  forwarding and NAT would need (not tested),
- an iptables example, marked "example only, not applied".

No firewall rule was applied to this host, and the Linux backend was not run.

## 5. Changes made in this review

| File | Change |
|---|---|
| `vpn_server.py` (`serve_tun`) | Before writing a decrypted inner datagram to the TUN device, check that it is IPv4 (length >= 20, version 4). Otherwise log "dropped inner datagram ... not IPv4" |
| `vpn_client.py` (`run_tun`) | Same check on the receive side |
| `test_tun.py` | New test `test_authenticated_non_ipv4_inner_is_not_written_to_device`: a sealed IPv6-looking inner datagram from an authenticated peer must not reach the device |
| `README.md` | Test count corrected to 120. Key checking paragraph and command. Firewall section |
| `THREAT_MODEL.md` | Section 6 row for non-IPv4 frames now covers the receive side and names the new test |
| `NETWORK_SECURITY_REVIEW.md` | New. This file |

The gap: the send side already dropped non-IPv4 frames (`is_ipv4` and `len >= 20` checks before
`send_inner`), but the receive side wrote whatever the authenticated peer sent. The peer still has to
hold the key, so this is a hardening gap, not a remote hole. The fix is one check on each side.

Not changed: the wire format, the handshake, the AEAD, the replay window, the rekey timers, and the
key loading. No new dependencies. `analysis/` was not touched.

## 6. Findings, ranked

1. **Fixed.** Receive side wrote non-IPv4 inner datagrams to the TUN device (Ch. 9 next-header
   discipline, applied to the device boundary). Test added.
2. **Fixed (documentation).** No firewall checklist for the UDP port, tunnel prefix, interface,
   bind address, or anti-spoofing (Ch. 12). Section added to README.
3. **Decision recorded.** Key distribution is manual and out of band, with no PKI (Ch. 4, Ch. 9.5).
   Fingerprint check added.
4. **Gap, not fixed.** SA lifetime has no byte count (Ch. 9.2 allows a lifetime by time or by bytes).
   Adding one is a behaviour change, not a small fix, so it is left open.
5. **Deliberate divergence.** Not RFC ESP. Pad 0 to 3 bytes, no TFC padding, no ESN, no SPI plus
   destination lookup, and a Noise IK handshake in place of IKE (Ch. 9).
6. **Changed in the second pass.** The endpoint now moves only after the inner-source check. Before, it moved
   first, so a packet the check refused could still move it. An INIT no longer moves the endpoint at all.
   Tests: `test_refused_packet_does_not_promote_or_roam`, `test_replayed_init_after_restart_does_not_move_endpoint`
   (test_hardening.py).

## 7. Test results

Run from `tunnel\`, with `python -m unittest`, Python 3.13.14.

- Before any change: `Ran 119 tests in 7.610s` and `OK`.
- After the changes: `Ran 120 tests in 8.674s` and `OK`.
- At the second hardening pass: `Ran 170 tests in 15.908s` and `OK`. Current (finalization pass): `Ran 179 tests in 15.744s` and `OK` (the 119, 120 and 170 above are history).
- `python -m unittest test_tun.TunLoopTests -v` (4 tests) passed.
- The new test was run against a scratch copy of the tree with the receive check reverted. It failed
  with `AssertionError: TimeoutError not raised`, which shows it catches the gap. The copy was deleted.
- Padding check, run here: for inner lengths 0 to 1400, 1401 round trips succeeded, and no padded
  plaintext was a length other than a multiple of 4.
- Fingerprint command from `README.md`, run here on a generated key: printed a 64-character SHA-256
  digest over 32 bytes.

## 8. Not verified

- No interoperability with RFC 4303 ESP, RFC 7296 IKE, the book's examples, or any real IPsec stack.
- The Linux TUN device and every firewall rule in the README: not applied and not run on a Linux
  kernel (see `README.md`, "Verified and not verified").
- The padding content of the book's ESP is not described in the text read, so the pad byte pattern is
  not checked against the book or RFC 4303.
- TLS comparison is from the book's description only. No TLS code was run.
- No formal analysis. The padding and round-trip checks are on the code paths shown.
- Byte-count SA lifetime, ESN, and traffic-flow padding are not implemented.
