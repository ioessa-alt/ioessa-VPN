"""Wire-format analyzer: what a passive observer sees in an outer (ciphertext) capture.

For every UDP payload in a pcap it reads the leading message type and the length, lists the
cleartext fields of that message type, and runs three checks:

  * length and reserved-byte checks against the message formats in vpn_handshake.py and vpn_transport.py
  * plaintext markers (--marker TEXT or --marker-hex HEX): is the marker in a cleartext
    field, or anywhere in the payload bytes?
  * static public keys (--static-pub BASE64_OR_HEX, repeatable): does a cleartext field equal
    the key, or does the key appear in the payload bytes?

Public keys are not secrets, so passing them here is fine. Private keys are never needed.
This module is stdlib only. The spec lengths are copied from vpn_constants.py, and
analysis/test_leak.py checks that the copies match.

Cleartext fields by type (vpn_handshake.py and vpn_transport.py, V-D):
  INIT   (1, 1236 B): type, reserved, sender index, ephemeral public key, ML-KEM-768 ciphertext
                      (static key, timestamp, mac1, mac2 are opaque)
  RESP   (2, 1180 B): type, reserved, sender index, receiver index, ephemeral public key, ML-KEM-768 ciphertext
  COOKIE (3,  72 B): type, reserved, receiver index, salt
  DATA   (4, >=34 B): type, reserved, receiver index, 64-bit counter (ciphertext follows)

Usage:
  python analysis/analyze.py outer.pcap [--port 45500] [--marker TEXT] [--static-pub KEY]
Exit status: 0 no findings, 1 the file could not be read, 2 a leak or a format problem.
"""
import argparse
import base64
import binascii
import struct
import sys
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pcap import PcapError, parse_ipv4_udp, read_pcap  # noqa: E402

MSG_NAMES = {1: "INIT", 2: "RESP", 3: "COOKIE", 4: "DATA"}
WIRE_VERSION = 2                          # vpn_constants.WIRE_VERSION; byte 1 of every datagram
SPEC_LEN = {1: 1236, 2: 1180, 3: 72}      # fixed sizes; DATA has a minimum instead
DATA_MIN_LEN = 16 + 4 + 16                # header (16), smallest padded body (4, an empty keepalive), tag (16) = 36

# Cleartext regions per type: (name, start, end). The bytes are visible to a passive observer.
CLEAR_FIELDS: Dict[int, List[Tuple[str, int, int]]] = {
    1: [("type", 0, 1), ("reserved", 1, 4), ("sender", 4, 8), ("ephemeral", 8, 40), ("ml_kem_ciphertext", 40, 1128)],
    2: [("type", 0, 1), ("reserved", 1, 4), ("sender", 4, 8), ("receiver", 8, 12), ("ephemeral", 12, 44),
        ("ml_kem_ciphertext", 44, 1132)],
    3: [("type", 0, 1), ("reserved", 1, 4), ("receiver", 4, 8), ("salt", 8, 40)],
    4: [("type", 0, 1), ("reserved", 1, 4), ("receiver", 4, 8), ("counter", 8, 16)],
}

@dataclass
class Message:
    index: int
    ts: float
    src: str
    dst: str
    mtype: int
    length: int
    payload: bytes
    cleartext: Dict[str, bytes] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return MSG_NAMES.get(self.mtype, f"unknown({self.mtype})")


@dataclass
class Report:
    path: str
    messages: List[Message] = field(default_factory=list)
    non_udp: int = 0
    skipped_port: int = 0
    marker_in_cleartext: List[str] = field(default_factory=list)
    marker_in_payload: List[str] = field(default_factory=list)
    key_equal_cleartext: List[str] = field(default_factory=list)
    key_in_payload: List[str] = field(default_factory=list)
    format_problems: List[str] = field(default_factory=list)

    @property
    def findings(self) -> List[str]:
        out = []
        out += [f"marker {m}" for m in self.marker_in_cleartext]
        out += [f"marker {m} (payload bytes)" for m in self.marker_in_payload]
        out += [f"static key {k} equals a cleartext field" for k in self.key_equal_cleartext]
        out += [f"static key {k} (payload bytes)" for k in self.key_in_payload]
        out += self.format_problems
        return out


def parse_key(text: str) -> bytes:
    """Accept a base64 (44 chars) or hex (64 chars) X25519 public key."""
    t = text.strip()
    if len(t) == 64:
        try:
            return binascii.unhexlify(t)
        except binascii.Error:
            pass
    raw = base64.b64decode(t, validate=True)
    if len(raw) != 32:
        raise ValueError("public key must be 32 bytes (base64 or 64 hex digits)")
    return raw


def _classify(msg: Message) -> None:
    """Fill msg.cleartext and msg.problems from the type and length."""
    p = msg.payload
    if msg.mtype not in MSG_NAMES:
        msg.problems.append(f"unknown message type {msg.mtype}")
        return
    if msg.mtype in SPEC_LEN and msg.length != SPEC_LEN[msg.mtype]:
        msg.problems.append(f"{msg.name} length {msg.length}, spec {SPEC_LEN[msg.mtype]}")
    if msg.mtype == 4 and msg.length < DATA_MIN_LEN:
        msg.problems.append(f"DATA length {msg.length} below minimum {DATA_MIN_LEN}")
    if msg.length < 4 or p[1] != WIRE_VERSION or p[2:4] != bytes(2):
        msg.problems.append("wire version or reserved bytes wrong")
    for name, start, end in CLEAR_FIELDS[msg.mtype]:
        if end is not None and end > msg.length:
            continue
        msg.cleartext[name] = p[start:end] if end is not None else p[start:]


def _fmt_field(name: str, value: bytes) -> str:
    if name in ("sender", "receiver"):
        return f"{name}={struct.unpack('<I', value)[0]:#010x}"
    if name == "counter":
        return f"counter={struct.unpack('<Q', value)[0]}"
    if name == "type":
        return f"type={value[0]}"
    if name == "reserved":
        return f"reserved={'ok' if value == bytes(3) else value.hex()}"
    if len(value) > 8:
        return f"{name}={value[:8].hex()}..({len(value)} B)"
    return f"{name}={value.hex()}"


def analyze(path: str, port: Optional[int] = None, markers: Sequence[bytes] = (),
            static_pubs: Sequence[bytes] = ()) -> Report:
    """Read the pcap and return a Report. Raises PcapError for a bad file."""
    pf = read_pcap(path)
    rep = Report(path)
    if pf.linktype != 101:
        raise PcapError(f"link type {pf.linktype}; this analyzer expects LINKTYPE_RAW (101)")
    for rec in pf.records:
        try:
            udp = parse_ipv4_udp(rec.data)
        except PcapError as e:
            rep.format_problems.append(f"packet {len(rep.messages) + rep.non_udp}: {e}")
            continue
        if udp is None:
            rep.non_udp += 1
            continue
        if port is not None and port not in (udp.src[1], udp.dst[1]):
            rep.skipped_port += 1
            continue
        p = udp.payload
        if not p:
            rep.format_problems.append(f"empty UDP payload at packet {rec.ts:.6f}")
            continue
        msg = Message(len(rep.messages) + 1, rec.ts, f"{udp.src[0]}:{udp.src[1]}",
                      f"{udp.dst[0]}:{udp.dst[1]}", p[0], len(p), p)
        _classify(msg)
        rep.messages.append(msg)
        for problem in msg.problems:
            rep.format_problems.append(f"message {msg.index} ({msg.name}): {problem}")

    for m in markers:
        label = m.decode("latin-1") if all(32 <= b < 127 for b in m) else m.hex()
        for msg in rep.messages:
            if any(m in v for v in msg.cleartext.values()):
                rep.marker_in_cleartext.append(f"{label!r} in message {msg.index}")
            if m in msg.payload:
                rep.marker_in_payload.append(f"{label!r} in message {msg.index}")
    for k in static_pubs:
        label = k.hex()[:16] + "..."
        for msg in rep.messages:
            if any(v == k for v in msg.cleartext.values()):
                rep.key_equal_cleartext.append(f"{label} in message {msg.index}")
            if k in msg.payload:
                rep.key_in_payload.append(f"{label} in message {msg.index}")
    return rep


def format_report(rep: Report, show_fields: bool = True) -> str:
    lines = [f"file: {rep.path}", f"UDP messages: {len(rep.messages)}"
             f"  (non-UDP skipped: {rep.non_udp}, other ports skipped: {rep.skipped_port})", ""]
    lines.append(f"{'#':>3}  {'time':>17}  {'src':>21} -> {'dst':<21}  {'type':<7} {'len':>5}  cleartext fields")
    for m in rep.messages:
        fields = ", ".join(_fmt_field(n, v) for n, v in m.cleartext.items()) if show_fields else ""
        flag = "  !" if m.problems else ""
        lines.append(f"{m.index:>3}  {m.ts:>17.6f}  {m.src:>21} -> {m.dst:<21}  {m.name:<7} {m.length:>5}  {fields}{flag}")
    counts: Dict[str, int] = {}
    for m in rep.messages:
        counts[m.name] = counts.get(m.name, 0) + 1
    lines.append("")
    lines.append("per type: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"))
    lines.append("format problems: " + (str(len(rep.format_problems)) if rep.format_problems else "none"))
    for p in rep.format_problems:
        lines.append(f"  - {p}")
    lines.append("findings: " + ("none" if not rep.findings else ""))
    for f_ in rep.findings:
        lines.append(f"  - {f_}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Analyze the outer (wire) capture of the VPN tunnel")
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=None, help="only UDP packets with this port (either end)")
    ap.add_argument("--marker", action="append", default=[], help="plaintext marker to search for (repeatable)")
    ap.add_argument("--marker-hex", action="append", default=[], help="marker as hex (repeatable)")
    ap.add_argument("--static-pub", action="append", default=[],
                    help="static public key (base64 or hex; repeatable). Public keys only.")
    ap.add_argument("--no-fields", action="store_true", help="omit the cleartext field column")
    args = ap.parse_args(argv)
    markers = [m.encode("utf-8") for m in args.marker] + [binascii.unhexlify(h) for h in args.marker_hex]
    try:
        keys = [parse_key(k) for k in args.static_pub]
        rep = analyze(args.pcap, args.port, markers, keys)
    except (PcapError, OSError, ValueError, binascii.Error) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(format_report(rep, not args.no_fields))
    return 2 if rep.findings else 0


if __name__ == "__main__":
    sys.exit(main())
