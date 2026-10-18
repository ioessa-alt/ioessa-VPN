"""Security policy (SPD) and IPv4 packet helpers."""
import ipaddress
import struct
from dataclasses import dataclass

from vpn_errors import ESPError

PROTECT, BYPASS, DISCARD = "protect", "bypass", "discard"
ANY = ipaddress.IPv4Network("0.0.0.0/0")
# Default inbound source policy (open issue 14): a peer may only send inner packets from the tunnel subnet
# used by the TUN demo (10.8.0.0/24). Configure allowed_ips per peer for anything else.
TUNNEL_NET = ipaddress.IPv4Network("10.8.0.0/24")


# ------------------------------------------------------------------ SPD / packets
@dataclass
class Policy:
    """SPD entry: which inner destinations to protect (section 8.7.3). First match wins."""
    net: ipaddress.IPv4Network
    action: str


def build_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    """Minimal valid IPv4 header (with checksum) so inner datagrams look real."""
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    csum = 0
    for i in range(0, 20, 2):
        csum += (hdr[i] << 8) | hdr[i + 1]
    csum = (csum & 0xFFFF) + (csum >> 16)
    csum = (~((csum & 0xFFFF) + (csum >> 16))) & 0xFFFF
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:] + payload


def parse_ipv4(pkt: bytes) -> tuple:
    """Return (src, dst, proto, payload) for an IPv4 datagram."""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        raise ESPError("not IPv4")
    ihl = (pkt[0] & 0x0F) * 4
    return (str(ipaddress.IPv4Address(pkt[12:16])), str(ipaddress.IPv4Address(pkt[16:20])),
            pkt[9], pkt[ihl:])


def describe(pkt: bytes, show_payload: bool = False) -> str:
    """One-line summary of an inner datagram. The payload is shown only on request."""
    src, dst, proto, payload = parse_ipv4(pkt)
    line = f"{src} -> {dst} proto={proto} len={len(pkt)}"
    return line + (f" payload={payload!r}" if show_payload else "")
