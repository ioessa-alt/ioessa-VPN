"""Tests for analyze.py: type and length per message, cleartext fields, and the leak checks.

Synthetic captures cover each check. One case builds a real INIT with vpn_handshake.make_initiation,
using keys that exist only in memory, to show the static key is not visible in the outer bytes.
"""
import base64
import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TUNNEL = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, TUNNEL)

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

import analyze  # noqa: E402
from analyze import analyze as run_analyze, main as analyze_main, parse_key  # noqa: E402
from pcap import PcapWriter, build_ipv4_udp  # noqa: E402
from vpn_constants import MSG_INIT, MSG_RESP, MSG_COOKIE, MSG_DATA  # noqa: E402
from vpn_handshake import make_initiation  # noqa: E402

CLIENT = ("127.0.0.1", 40000)
SERVER = ("127.0.0.1", 45500)


def _raw_pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _init(sender=0x01020304, eph=b"\x11" * 32, enc_static=b"\x22" * 48, ts=b"\x33" * 28) -> bytes:
    ct = b"\x5a" * 1088                                    # ML-KEM-768 ciphertext, opaque
    return (struct.pack("<BBxxI", MSG_INIT, 2, sender) + eph + ct + enc_static + ts + b"\x44" * 16 + bytes(16))


def _resp(sender=0x0A0B0C0D, receiver=0x01020304, eph=b"\x55" * 32) -> bytes:
    ct = b"\x6b" * 1088                                    # ML-KEM-768 ciphertext, opaque
    return struct.pack("<BBxxII", MSG_RESP, 2, sender, receiver) + eph + ct + b"\x66" * 16 + b"\x77" * 16 + bytes(16)


def _cookie() -> bytes:
    return struct.pack("<BBxxI", MSG_COOKIE, 2, 0x01020304) + b"\x77" * 32 + b"\x88" * 32


def _data(counter=5, body=b"\x99" * 20) -> bytes:
    return struct.pack("<BBxxIQ", MSG_DATA, 2, 0x0A0B0C0D, counter) + body + b"\xaa" * 16


class AnalyzeTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def capture(self, packets, name="outer.pcap"):
        """Write (payload, src, dst) datagrams as a pcap. A non-UDP entry is raw bytes."""
        path = os.path.join(self._tmp.name, name)
        with PcapWriter(path) as w:
            for i, item in enumerate(packets):
                if isinstance(item, bytes):
                    w.write(item, ts=100 + i)
                    continue
                payload, src, dst = item
                w.write(build_ipv4_udp(src[0], src[1], dst[0], dst[1], payload), ts=100 + i)
        return path


class TypeAndLengthTests(AnalyzeTestCase):
    def test_lists_each_message_with_type_length_and_cleartext(self):
        path = self.capture([(_init(), CLIENT, SERVER), (_resp(), SERVER, CLIENT),
                             (_cookie(), SERVER, CLIENT), (_data(), CLIENT, SERVER)])
        rep = run_analyze(path)
        self.assertEqual([m.name for m in rep.messages], ["INIT", "RESP", "COOKIE", "DATA"])
        self.assertEqual([m.length for m in rep.messages], [1236, 1180, 72, 52])
        self.assertEqual(rep.format_problems, [])
        self.assertEqual(rep.findings, [])
        init = rep.messages[0]
        self.assertEqual(struct.unpack("<I", init.cleartext["sender"])[0], 0x01020304)
        self.assertEqual(init.cleartext["ephemeral"], b"\x11" * 32)
        data = rep.messages[3]
        self.assertEqual(struct.unpack("<Q", data.cleartext["counter"])[0], 5)
        self.assertNotIn("ciphertext", data.cleartext)            # opaque, not listed as cleartext

    def test_wrong_length_and_reserved_bytes_are_flagged(self):
        short_init = _init()[:-1]                                  # 1235 bytes
        bad_resp = bytearray(_resp())
        bad_resp[2] = 1                                            # reserved byte set
        path = self.capture([(short_init, CLIENT, SERVER), (bytes(bad_resp), SERVER, CLIENT)])
        rep = run_analyze(path)
        problems = " | ".join(rep.format_problems)
        self.assertIn("INIT length 1235, spec 1236", problems)
        self.assertIn("(RESP): wire version or reserved bytes wrong", problems)
        self.assertTrue(rep.findings)

    def test_data_below_minimum_and_unknown_type_are_flagged(self):
        path = self.capture([(struct.pack("<BBxx", MSG_DATA, 2) + bytes(10), CLIENT, SERVER),
                             (b"\x09" + bytes(60), CLIENT, SERVER)])
        rep = run_analyze(path)
        problems = " | ".join(rep.format_problems)
        self.assertIn("DATA length 14 below minimum", problems)
        self.assertIn("unknown message type 9", problems)

    def test_non_udp_and_other_ports_are_counted_not_analyzed(self):
        tcp = bytearray(build_ipv4_udp("10.0.0.1", 1, "10.0.0.2", 2, b"x"))
        tcp[9] = 6
        path = self.capture([bytes(tcp), (_resp(), SERVER, CLIENT), (_data(), ("10.9.9.9", 9), ("10.9.9.8", 9))])
        rep = run_analyze(path, port=45500)
        self.assertEqual(rep.non_udp, 1)
        self.assertEqual(rep.skipped_port, 1)
        self.assertEqual([m.name for m in rep.messages], ["RESP"])


class LeakCheckTests(AnalyzeTestCase):
    def test_static_key_equal_to_a_cleartext_field_is_flagged(self):
        key = b"\xc3" * 32
        path = self.capture([(_init(eph=key), CLIENT, SERVER)])
        rep = run_analyze(path, static_pubs=[key])
        self.assertEqual(len(rep.key_equal_cleartext), 1)
        self.assertEqual(len(rep.key_in_payload), 1)
        self.assertTrue(any("equals a cleartext field" in f for f in rep.findings))

    def test_static_key_only_in_ciphertext_is_reported_as_payload_only(self):
        key = b"\xd4" * 32
        msg = _init(enc_static=key + bytes(16))            # 48 bytes, key inside the encrypted field
        path = self.capture([(msg, CLIENT, SERVER)])
        rep = run_analyze(path, static_pubs=[key])
        self.assertEqual(rep.key_equal_cleartext, [])
        self.assertEqual(len(rep.key_in_payload), 1)

    def test_marker_in_cleartext_field_and_in_ciphertext(self):
        marker = b"PLAINTEXT-MARKER-XYZ"
        in_clear = _resp(eph=marker + bytes(32 - len(marker)))
        in_cipher = _data(body=marker + b"\x00" * 4)
        path = self.capture([(in_clear, SERVER, CLIENT), (in_cipher, CLIENT, SERVER)])
        rep = run_analyze(path, markers=[marker])
        self.assertEqual(len(rep.marker_in_cleartext), 1)          # the RESP ephemeral field
        self.assertIn("message 1", rep.marker_in_cleartext[0])
        self.assertEqual(len(rep.marker_in_payload), 2)            # both messages, raw bytes
        self.assertTrue(rep.findings)

    def test_clean_capture_has_no_findings(self):
        path = self.capture([(_init(), CLIENT, SERVER), (_data(), CLIENT, SERVER)])
        rep = run_analyze(path, markers=[b"NOT-PRESENT-MARKER"], static_pubs=[b"\xee" * 32])
        self.assertEqual(rep.findings, [])


class RealHandshakeTests(AnalyzeTestCase):
    def test_real_init_hides_the_initiators_static_key(self):
        init_priv = X25519PrivateKey.generate()          # in memory only; never written anywhere
        resp_priv = X25519PrivateKey.generate()
        init_pub = _raw_pub(init_priv)
        resp_pub = _raw_pub(resp_priv)
        init_kem = mlkem.MLKEM768PrivateKey.generate()
        resp_kem_pub = mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw()
        msg, _state = make_initiation(init_priv, init_pub, init_kem, resp_pub, resp_kem_pub, b"", 0x1234ABCD, bytes(12))
        self.assertEqual(len(msg), 1236)
        path = self.capture([(msg, CLIENT, SERVER)])
        rep = run_analyze(path, static_pubs=[init_pub, resp_pub])
        self.assertEqual(rep.format_problems, [])
        self.assertEqual(rep.key_equal_cleartext, [])
        self.assertEqual(rep.key_in_payload, [])
        self.assertEqual(rep.messages[0].cleartext["sender"], struct.pack("<I", 0x1234ABCD))


class CliTests(AnalyzeTestCase):
    def test_exit_codes_and_report(self):
        import base64
        clean = self.capture([(_init(), CLIENT, SERVER)], "clean.pcap")
        leaky = self.capture([(_init(eph=b"\xc3" * 32), CLIENT, SERVER)], "leaky.pcap")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(analyze_main([clean]), 0)
            key_b64 = base64.b64encode(b"\xc3" * 32).decode()
            self.assertEqual(analyze_main([leaky, "--static-pub", key_b64]), 2)
        self.assertIn("UDP messages: 1", out.getvalue())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(analyze_main([os.path.join(self._tmp.name, "missing.pcap")]), 1)
        self.assertIn("error:", err.getvalue())

    def test_parse_key_accepts_base64_and_hex(self):
        raw = b"\x01" * 32
        import base64
        self.assertEqual(parse_key(base64.b64encode(raw).decode()), raw)
        self.assertEqual(parse_key(raw.hex()), raw)
        with self.assertRaises(ValueError):
            parse_key(base64.b64encode(b"short").decode())


if __name__ == "__main__":
    unittest.main()
