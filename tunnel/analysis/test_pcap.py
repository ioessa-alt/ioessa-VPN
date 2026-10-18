"""Tests for pcap.py: the savefile header bytes, record headers, round trip, and IPv4/UDP framing.

Run from anywhere:  python -m unittest discover -s analysis -p "test_*.py"
"""
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pcap  # noqa: E402
from pcap import PcapError, PcapWriter, build_ipv4_udp, ipv4_checksum, parse_ipv4_udp, read_pcap  # noqa: E402


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _sample_ip(n: int = 40) -> bytes:
    return build_ipv4_udp("10.8.0.2", 5000, "10.8.0.1", 6000, bytes(i % 256 for i in range(n)), ident=7)


class PcapWriterHeaderTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "t.pcap")

    def tearDown(self):
        self._tmp.cleanup()

    def test_empty_file_is_exactly_the_global_header(self):
        PcapWriter(self.path).close()
        data = _read(self.path)
        # magic d4 c3 b2 a1 is 0xa1b2c3d4 stored little-endian (microsecond resolution)
        expected = (b"\xd4\xc3\xb2\xa1"
                    + struct.pack("<HH", 2, 4)          # version 2.4
                    + struct.pack("<i", 0)              # thiszone
                    + struct.pack("<I", 0)              # sigfigs
                    + struct.pack("<I", 65535)          # snaplen
                    + struct.pack("<I", 101))           # network = LINKTYPE_RAW
        self.assertEqual(len(expected), 24)
        self.assertEqual(data, expected)

    def test_record_header_fields(self):
        ip = _sample_ip(40)
        with PcapWriter(self.path) as w:
            w.write(ip, ts=1700000000.25)
        data = _read(self.path)
        self.assertEqual(len(data), 24 + 16 + len(ip))
        sec, usec, incl, orig = struct.unpack_from("<IIII", data, 24)
        self.assertEqual((sec, usec), (1700000000, 250000))
        self.assertEqual((incl, orig), (len(ip), len(ip)))
        self.assertEqual(data[40:], ip)

    def test_round_trip_reads_back_linktype_and_records(self):
        ips = [_sample_ip(n) for n in (0, 1, 33, 400)]
        with PcapWriter(self.path) as w:
            for i, ip in enumerate(ips):
                w.write(ip, ts=1_000 + i + 0.5)
        pf = read_pcap(self.path)
        self.assertEqual(pf.linktype, 101)
        self.assertEqual(pf.snaplen, 65535)
        self.assertEqual([r.data for r in pf.records], ips)
        self.assertEqual([r.ts for r in pf.records], [1_000.5, 1_001.5, 1_002.5, 1_003.5])

    def test_rejects_non_ip_and_empty_packets(self):
        with PcapWriter(self.path) as w:
            with self.assertRaises(ValueError):
                w.write(b"")
            with self.assertRaises(ValueError):
                w.write(b"\x00" * 20)           # version nibble 0 is not IP

    def test_reader_accepts_big_endian_file(self):
        ip = _sample_ip(10)
        raw = (b"\xa1\xb2\xc3\xd4" + struct.pack(">HHiIII", 2, 4, 0, 0, 65535, 101)
               + struct.pack(">IIII", 5, 6, len(ip), len(ip)) + ip)
        self.assertEqual(read_pcap(self._write_raw(raw)).records[0].data, ip)

    def test_reader_rejects_bad_magic_and_truncation(self):
        with self.assertRaises(PcapError):
            read_pcap(self._write_raw(b"\x00" * 24))
        with self.assertRaises(PcapError):
            read_pcap(self._write_raw(b"\xd4\xc3\xb2\xa1"))      # shorter than 24 bytes
        with PcapWriter(self.path) as w:
            w.write(_sample_ip(40))
        raw = _read(self.path)
        with self.assertRaises(PcapError):
            read_pcap(self._write_raw(raw[:-5]))                  # truncated record data
        with self.assertRaises(PcapError):
            read_pcap(self._write_raw(raw[:-(len(raw) - 30)]))    # truncated record header

    def _write_raw(self, raw: bytes) -> str:
        path = os.path.join(self._tmp.name, "raw.pcap")
        with open(path, "wb") as f:
            f.write(raw)
        return path


class IpUdpFramingTests(unittest.TestCase):
    def test_ipv4_header_checksum_verifies(self):
        pkt = build_ipv4_udp("127.0.0.1", 45500, "127.0.0.1", 40000, b"hello", ident=1)
        self.assertEqual(pkt[0], 0x45)
        self.assertEqual(ipv4_checksum(pkt[:20]), 0)  # a valid header sums to zero
        self.assertEqual(struct.unpack_from("!H", pkt, 2)[0], len(pkt))
        self.assertEqual(pkt[9], 17)

    def test_parse_returns_addresses_and_payload(self):
        payload = bytes(range(256)) * 2
        pkt = build_ipv4_udp("192.0.2.1", 1111, "192.0.2.2", 2222, payload)
        udp = parse_ipv4_udp(pkt)
        self.assertEqual(udp.src, ("192.0.2.1", 1111))
        self.assertEqual(udp.dst, ("192.0.2.2", 2222))
        self.assertEqual(udp.payload, payload)

    def test_parse_skips_non_udp_and_rejects_inconsistent_headers(self):
        tcp_like = bytearray(build_ipv4_udp("10.0.0.1", 1, "10.0.0.2", 2, b"x"))
        tcp_like[9] = 6
        self.assertIsNone(parse_ipv4_udp(bytes(tcp_like)))
        self.assertIsNone(parse_ipv4_udp(b"\x60" + bytes(39)))      # IPv6 is not handled here
        bad = bytearray(build_ipv4_udp("10.0.0.1", 1, "10.0.0.2", 2, b"abc"))
        struct.pack_into("!H", bad, 2, 9000)                        # total length beyond the data
        with self.assertRaises(PcapError):
            parse_ipv4_udp(bytes(bad))

    def test_oversize_datagram_rejected(self):
        with self.assertRaises(ValueError):
            build_ipv4_udp("10.0.0.1", 1, "10.0.0.2", 2, bytes(65535))


if __name__ == "__main__":
    unittest.main()
