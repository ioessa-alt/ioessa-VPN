"""Stdlib pcap (libpcap savefile) writer and reader, for raw IP packets (LINKTYPE_RAW, 101).

File layout (libpcap savefile format, as used by tcpdump and Wireshark):
  global header, 24 bytes:  magic u32, version_major u16, version_minor u16, thiszone i32,
                            sigfigs u32, snaplen u32, network u32 (link type)
  per packet, 16-byte record header then the captured bytes:
                            ts_sec u32, ts_usec u32, incl_len u32, orig_len u32
Fields are written little-endian. The magic 0xa1b2c3d4 is then stored as d4 c3 b2 a1, which is
how readers detect byte order. Version 2.4, thiszone 0, sigfigs 0, snaplen 65535.

The reader also accepts big-endian files and the nanosecond magic (0xa1b23c4d).
With LINKTYPE_RAW each record starts with an IP header (version nibble 4 or 6).
"""
import ipaddress
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

MAGIC_US = 0xA1B2C3D4
MAGIC_NS = 0xA1B23C4D
VERSION_MAJOR = 2
VERSION_MINOR = 4
SNAPLEN = 65535
LINKTYPE_RAW = 101
GLOBAL_HDR_LE = struct.Struct("<IHHiIII")   # 24 bytes
RECORD_HDR_LE = struct.Struct("<IIII")      # 16 bytes
IPPROTO_UDP = 17


class PcapError(Exception):
    """Malformed or unsupported pcap data."""


class PcapWriter:
    """Writes a classic pcap file with LINKTYPE_RAW. Flushes after every packet, so a reader can
    see the packets while the writer is still open. Thread-safe."""

    def __init__(self, path: str, snaplen: int = SNAPLEN):
        self._f = open(path, "wb")
        self._snaplen = snaplen
        self._lock = threading.Lock()
        self._f.write(GLOBAL_HDR_LE.pack(MAGIC_US, VERSION_MAJOR, VERSION_MINOR, 0, 0, snaplen, LINKTYPE_RAW))
        self._f.flush()

    def write(self, pkt: bytes, ts: Optional[float] = None) -> None:
        if not isinstance(pkt, (bytes, bytearray)) or len(pkt) == 0:
            raise ValueError("packet must be non-empty bytes")
        if pkt[0] >> 4 not in (4, 6):
            raise ValueError("LINKTYPE_RAW packets must start with an IPv4 or IPv6 header")
        ts = time.time() if ts is None else ts
        sec = int(ts)
        usec = min(max(int((ts - sec) * 1_000_000), 0), 999_999)
        incl = min(len(pkt), self._snaplen)
        with self._lock:
            self._f.write(RECORD_HDR_LE.pack(sec, usec, incl, len(pkt)))
            self._f.write(bytes(pkt[:incl]))
            self._f.flush()

    def close(self) -> None:
        with self._lock:
            if not self._f.closed:
                self._f.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


@dataclass
class Record:
    ts: float
    orig_len: int
    data: bytes


@dataclass
class PcapFile:
    linktype: int
    snaplen: int
    records: List[Record] = field(default_factory=list)


def read_pcap(path: str) -> PcapFile:
    """Read a classic pcap file. Raises PcapError on bad magic, truncation, or a bad record."""
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < 24:
        raise PcapError("file shorter than the 24-byte global header")
    magic_le = struct.unpack_from("<I", raw, 0)[0]
    if magic_le in (MAGIC_US, MAGIC_NS):
        end, nanos = "<", magic_le == MAGIC_NS
    elif struct.unpack_from(">I", raw, 0)[0] in (MAGIC_US, MAGIC_NS):
        end, nanos = ">", struct.unpack_from(">I", raw, 0)[0] == MAGIC_NS
    else:
        raise PcapError("not a classic pcap file (bad magic)")
    _magic, _maj, _min, _tz, _sig, snaplen, network = struct.unpack_from(end + "IHHiIII", raw, 0)
    out = PcapFile(linktype=network, snaplen=snaplen)
    rec = struct.Struct(end + "IIII")
    off = 24
    while off < len(raw):
        if off + 16 > len(raw):
            raise PcapError("truncated record header")
        sec, frac, incl, orig = rec.unpack_from(raw, off)
        off += 16
        if incl > snaplen or incl > orig:
            raise PcapError("record length exceeds snaplen or original length")
        if off + incl > len(raw):
            raise PcapError("truncated record data")
        scale = 1e9 if nanos else 1e6
        out.records.append(Record(sec + frac / scale, orig, raw[off:off + incl]))
        off += incl
    return out


def ipv4_checksum(header: bytes) -> int:
    """RFC 1071 one's-complement checksum over a header whose checksum field is zero."""
    if len(header) % 2:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4_udp(src_ip: str, sport: int, dst_ip: str, dport: int, payload: bytes, ident: int = 0) -> bytes:
    """Wrap a UDP payload in an IPv4 header (no options, DF set, TTL 64) and a UDP header.
    The UDP checksum is left at zero, which IPv4 allows (it means "not computed")."""
    udp_len = 8 + len(payload)
    total = 20 + udp_len
    if total > 65535:
        raise ValueError("datagram too large for IPv4")
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident & 0xFFFF, 0x4000, 64, IPPROTO_UDP, 0,
                      ipaddress.IPv4Address(src_ip).packed, ipaddress.IPv4Address(dst_ip).packed)
    hdr = hdr[:10] + struct.pack("!H", ipv4_checksum(hdr)) + hdr[12:]
    return hdr + struct.pack("!HHHH", sport, dport, udp_len, 0) + payload


@dataclass
class UdpPacket:
    src: Tuple[str, int]
    dst: Tuple[str, int]
    payload: bytes


def parse_ipv4_udp(pkt: bytes) -> Optional[UdpPacket]:
    """Return the UDP datagram in an IPv4 packet, or None if it is not IPv4/UDP.
    Raises PcapError if the IPv4 or UDP header is inconsistent."""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl:
        raise PcapError("bad IPv4 header length")
    total = struct.unpack_from("!H", pkt, 2)[0]
    if total > len(pkt) or total < ihl + 8:
        raise PcapError("bad IPv4 total length")
    if pkt[9] != IPPROTO_UDP:
        return None
    src = str(ipaddress.IPv4Address(pkt[12:16]))
    dst = str(ipaddress.IPv4Address(pkt[16:20]))
    sport, dport, udp_len, _csum = struct.unpack_from("!HHHH", pkt, ihl)
    if udp_len < 8 or ihl + udp_len > total:
        raise PcapError("bad UDP length")
    return UdpPacket((src, sport), (dst, dport), bytes(pkt[ihl + 8:ihl + udp_len]))
