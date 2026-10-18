"""Unit tests for the WireGuard-style tunnel core. Run from this folder with: python -m unittest

No real sockets, no admin rights. Keys are generated per run and never stored in source.
Inner datagrams are simulated IPv4 packets. Test names from the earlier ESP/IKE prototype are
kept where the behaviour still holds. Tests that changed on purpose say so in their docstring.
"""
import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import tempfile
import time
import unittest
from typing import Optional
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vpn_client import _recv_from
from vpn_server import RejectCounter, serve, serve_tun
from vpn_constants import (HS_FAIL, INIT_LEN, INIT_MAC1, KEM_CT_LEN, KEM_EK_LEN, KEY_ENV, KEY_FILE_ENV, LOG_BURST,
                           LOG_RATE, MAX_ESP, MAX_INNER, MSG_COOKIE, MSG_DATA, MSG_INIT, MSG_RESP,
                           REKEY_AFTER_MESSAGES, REKEY_JITTER_MAX, REKEY_MARGIN, RESP_LEN, RESP_MAC1, SEQ_MAX,
                           STANDARD, STRICT, TAG_LEN, WINDOW)
from vpn_errors import ESPError, HandshakeError, RekeyRequired
from vpn_crypto import (_dh, _h, _hmac_b2s, _is_low_order, _kdf, _mac, _pub_raw, _tai64n, encode_key,
                        generate_keypair, private_key_from_b64, public_key_from_b64)
from vpn_keyfiles import load_static_private
from vpn_handshake import (_check_mac1, _check_mac2, _cookie_key, _cookie_tau, _mac1_key, _transport_keys,
                           consume_cookie, consume_initiation, consume_response, finish_initiation, InitInfo,
                           make_cookie_reply, make_initiation, make_response)
from vpn_ip import build_ipv4, BYPASS, parse_ipv4, Policy, PROTECT
from vpn_transport import open_data, ReplayWindow, seal_data, Session
from vpn_node import handshake_local, Node, Peer
from vpn_tun import TunDevice

A_ADDR = ("127.0.0.1", 1)   # client endpoint in these tests
B_ADDR = ("127.0.0.1", 2)   # server endpoint
PSK = os.urandom(32)        # generated per run, never stored in source
ANY = ipaddress.IPv4Network("0.0.0.0/0")
PROTECT_ALL = [Policy(ANY, PROTECT)]


class FakeClock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def pair(clock=None, psk=b""):
    """Two nodes that completed the handshake. Both sides may send with PROTECT for all."""
    a, b = handshake_local(psk=psk, clock=clock, addr_a=A_ADDR, addr_b=B_ADDR)
    a.peers[b.pub].spd = list(PROTECT_ALL)
    b.peers[a.pub].spd = list(PROTECT_ALL)
    return a, b


def unfinished(psk=b"", clock=None):
    """Client A has sent INIT to server B, and B has not answered yet. Returns (a, b, pa, init)."""
    clk = clock or time.monotonic
    a = Node(X25519PrivateKey.generate(), psk, clk)
    b = Node(X25519PrivateKey.generate(), psk, clk)
    pa = a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
    b.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
    (init, _), = a.initiate(pa, clk())
    return a, b, pa, init


def remac1(msg: bytes, off: int, recv_pub: bytes, psk: bytes) -> bytes:
    """Recompute mac1 after an edit, as an attacker who knows the public key could."""
    return msg[:off] + _mac(_mac1_key(recv_pub), msg[:off]) + msg[off + 16:]


def forge_init(recv_pub: bytes, psk: bytes = b"", eph: bytes = None) -> bytes:
    """An INIT with a valid mac1 and random encrypted fields. The AEAD checks will fail."""
    eph = eph if eph is not None else os.urandom(32)
    body = struct.pack("<BBxxI", MSG_INIT, 2, 1234) + eph + os.urandom(INIT_MAC1 - 40)
    return body + _mac(_mac1_key(recv_pub), body) + bytes(16)


def recv_session(node: Node, wire: bytes):
    """The receiving session a packet's index points at."""
    return node.sessions[struct.unpack_from("<I", wire, 4)[0]][1]


class FakeSock:
    """Minimal stand-in for a UDP socket. `on_send` lets a test react to replies in the same
    serve() run, so one run can cover a handshake and then data packets."""

    def __init__(self, inbox=(), on_send=None):
        self.inbox = list(inbox)
        self.sent = []
        self.on_send = on_send

    def settimeout(self, t):
        pass

    def recvfrom(self, n):
        if not self.inbox:
            raise socket.timeout()
        item = self.inbox.pop(0)
        if isinstance(item, BaseException):     # an error queued by the test, raised like a socket would
            raise item
        return item

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        if self.on_send:
            self.on_send(data, addr)
        return len(data)


# ================================================================ handshake
class HandshakeTests(unittest.TestCase):
    def test_handshake_produces_matching_sas(self):
        """The handshake completes and both sides hold the same two transport keys."""
        a, b = pair()
        sa = a.peers[b.pub].current
        sb = b.sessions[sa.remote_index][1]
        self.assertEqual(sa.local_index, sb.remote_index)
        self.assertEqual(sa.send_key, sb.recv_key)
        self.assertEqual(sa.recv_key, sb.send_key)
        self.assertNotEqual(sa.send_key, sa.recv_key)     # the two directions differ
        self.assertIsNotNone(b.peers[a.pub].current)       # the responder promoted on first data
        self.assertNotIn(repr(sa.send_key.hex()), repr(sa))  # keys are not printed

    def test_psk_mode_handshake_completes(self):
        """Optional PSK mode (V-B) works when both ends have it, and is off by default."""
        a, b = pair(psk=PSK)
        self.assertIsNotNone(a.peers[b.pub].current)
        self.assertEqual(pair()[0].psk, b"")

    def test_wrong_psk_fails_authentication(self):
        """A responder with a different PSK does not answer. The mac1 check fails silently."""
        a = Node(X25519PrivateKey.generate(), os.urandom(32))
        b = Node(X25519PrivateKey.generate(), PSK)
        pa = a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
        b.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
        (init, _), = a.initiate(pa)
        self.assertEqual(b.handle(init, A_ADDR).send, [])

    def test_tampered_auth_message_rejected(self):
        """Changed RESP bytes (with mac1 recomputed) fail the AEAD check, so no session is made.
        Changed to test the response's encrypted part, since AUTH_I/AUTH_R no longer exist."""
        a, b, pa, init = unfinished()
        (resp, _), = b.handle(init, A_ADDR).send
        bad = bytearray(resp)
        bad[44] ^= 0x01                                    # the encrypted empty payload
        act = a.handle(remac1(bytes(bad), RESP_MAC1, a.pub, b""), B_ADDR)
        self.assertIsNone(pa.current)
        self.assertTrue(any(HS_FAIL in e for e in act.events), act.events)


class EspTests(unittest.TestCase):
    """Transport (V-D6): the data path, replay window, padding and size bounds."""

    def test_round_trip_both_directions(self):
        a, b = pair()
        pkt = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"payload " * 10)
        wire, _ = a.send(a.peers[b.pub], pkt)
        self.assertEqual(b.handle(wire, A_ADDR).inner, pkt)
        wire, _ = b.send(b.peers[a.pub], pkt)
        self.assertEqual(a.handle(wire, B_ADDR).inner, pkt)

    def test_tampered_ciphertext_rejected(self):
        a, b = pair()
        sess = a.peers[b.pub].current
        wire = bytearray(seal_data(sess, b"hello world", 1000.0))
        wire[-1] ^= 0x01
        with self.assertRaises(ESPError) as cm:
            open_data(recv_session(b, bytes(wire)), bytes(wire))
        self.assertEqual(cm.exception.reason, "auth failed")

    def test_tampered_header_rejected(self):
        """The 16-byte header is AEAD associated data (kept stricter than the paper)."""
        a, b = pair()
        wire = bytearray(seal_data(a.peers[b.pub].current, b"hello world", 1000.0))
        wire[8] ^= 0x01                                    # low byte of the counter: stays fresh
        with self.assertRaises(ESPError) as cm:
            open_data(recv_session(b, bytes(wire)), bytes(wire))
        self.assertEqual(cm.exception.reason, "auth failed")

    def test_replayed_packet_rejected(self):
        a, b = pair()
        wire = seal_data(a.peers[b.pub].current, b"once only", 1000.0)
        rs = recv_session(b, wire)
        self.assertEqual(open_data(rs, wire), b"once only")
        with self.assertRaises(ESPError) as cm:
            open_data(rs, wire)
        self.assertEqual(cm.exception.reason, "replay")

    def test_out_of_window_sequence_rejected(self):
        a, b = pair()
        sess = a.peers[b.pub].current
        packets = [seal_data(sess, bytes([i]), 1000.0) for i in range(70)]
        rs = recv_session(b, packets[0])
        self.assertEqual(open_data(rs, packets[69]), bytes([69]))
        with self.assertRaises(ESPError) as cm:
            open_data(rs, packets[5])                       # distance 64: outside
        self.assertEqual(cm.exception.reason, "out of window")
        self.assertEqual(open_data(rs, packets[6]), bytes([6]))   # distance 63: inside

    def test_wrong_spi_rejected(self):
        """Test name kept from the ESP prototype. The 'SPI' is now the receiver index."""
        a, b = pair()
        wire = bytearray(seal_data(a.peers[b.pub].current, b"x", 1000.0))
        wire[4:8] = struct.pack("<I", (struct.unpack_from("<I", wire, 4)[0] ^ 0x5A5A5A5A) & 0xFFFFFFFF)
        act = b.handle(bytes(wire), A_ADDR)
        self.assertTrue(any("unknown index" in e for e in act.events), act.events)
        self.assertIsNone(act.inner)

    def test_padding_is_stripped(self):
        a, b = pair()
        sess = a.peers[b.pub].current
        for n in range(0, 61):
            inner = bytes(range(256))[:n]
            wire = seal_data(sess, inner, 1000.0)
            self.assertEqual((len(wire) - 16 - 16) % 4, 0, f"trailer not aligned for n={n}")
            self.assertEqual(open_data(recv_session(b, wire), wire), inner, f"n={n}")

    def test_sequence_limit_forces_rekey(self):
        a, _ = pair()
        sess = a.peers[next(iter(a.peers))].current
        sess.limit = sess.send_counter + 3
        for _ in range(3):
            seal_data(sess, b"ok", 1000.0)
        with self.assertRaises(RekeyRequired):
            seal_data(sess, b"too many", 1000.0)

    def test_size_bounds(self):
        a, b = pair()
        sess = a.peers[b.pub].current
        with self.assertRaises(ESPError):
            seal_data(sess, bytes(MAX_INNER + 1), 1000.0)
        rs = next(iter(b.sessions.values()))[1]
        oversized = bytes([MSG_DATA, 0, 0, 0]) + struct.pack("<I", rs.local_index) + bytes(MAX_ESP)
        with self.assertRaises(ESPError) as cm:
            open_data(rs, oversized)
        self.assertEqual(cm.exception.reason, "bad size")


class PolicyTests(unittest.TestCase):
    def test_spd_protect_bypass_discard(self):
        a, b = pair()
        pa = a.peers[b.pub]
        pa.spd = [Policy(ipaddress.IPv4Network("10.8.0.0/24"), PROTECT), Policy(ANY, BYPASS)]
        self.assertIsNotNone(a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"in")))
        self.assertIsNone(a.send(pa, build_ipv4("10.8.0.2", "8.8.8.8", 253, b"out")))
        pa.spd = []   # no matching policy: default is discard
        with self.assertRaises(ESPError):
            a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x"))

    def test_ipv4_checksum_is_valid(self):
        pkt = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"abc")
        total = sum((pkt[i] << 8) | pkt[i + 1] for i in range(0, 20, 2))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        self.assertEqual(total, 0xFFFF)
        self.assertEqual(parse_ipv4(pkt), ("10.8.0.2", "10.8.0.1", 253, b"abc"))


# ================================================================ crypto review (CRYPTO_REVIEW.md)
# Small-order X25519 u-coordinates: 0, 1, two order-8 points, and the non-canonical p-1, p, p+1.
LOW_ORDER_PUBLIC = [
    "00" * 32,
    "01" + "00" * 31,
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ec" + "ff" * 30 + "7f",
    "ed" + "ff" * 30 + "7f",
    "ee" + "ff" * 30 + "7f",
]


class CryptoReviewTests(unittest.TestCase):
    """Known-answer and definition checks for the hand-built primitives (book ch. 2, 3, 5).

    The BLAKE2s vectors are from RFC 7693 Appendix B and the official BLAKE2 KAT file. The
    HMAC and HKDF checks compare against the textbook definitions written out here. The
    official Noise test vectors could not be obtained, so the handshake is not checked against them.
    """

    def test_blake2s_rfc7693_abc(self):
        self.assertEqual(_h(b"abc").hex(),
                         "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")

    def test_blake2s_keyed_official_kat(self):
        key = bytes(range(32))     # official blake2s-kat.txt, key 00..1f
        cases = {
            b"": "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
            b"\x00": "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
            b"\x00\x01": "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803",
            bytes(range(64)): "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4",
        }
        for msg, want in cases.items():
            with self.subTest(length=len(msg)):
                self.assertEqual(_mac(key, msg, 32).hex(), want)

    def test_hmac_blake2s_is_rfc2104_hmac(self):
        """HMAC over BLAKE2s with block size 64, checked against the RFC 2104 formula."""
        def textbook(k, m):
            k = k.ljust(64, b"\x00")
            ipad = bytes(x ^ 0x36 for x in k)
            opad = bytes(x ^ 0x5C for x in k)
            return hashlib.blake2s(opad + hashlib.blake2s(ipad + m).digest()).digest()

        self.assertEqual(hashlib.blake2s().block_size, 64)
        for k, m in [(bytes(32), b""), (bytes(range(32)), b"Hi There"), (bytes(range(64)), b"x" * 200)]:
            with self.subTest(klen=len(k), mlen=len(m)):
                self.assertEqual(_hmac_b2s(k, m), textbook(k, m))

    def test_kdf_is_noise_hkdf_with_two_outputs(self):
        """Noise spec HKDF(ck, ikm, 2): temp = HMAC(ck, ikm); o1 = HMAC(temp, 0x01); o2 = HMAC(temp, o1 | 0x02)."""
        ck, ikm = bytes(range(32)), b"ioessa test input"
        temp = hmac.new(ck, ikm, hashlib.blake2s).digest()
        o1 = hmac.new(temp, b"\x01", hashlib.blake2s).digest()
        o2 = hmac.new(temp, o1 + b"\x02", hashlib.blake2s).digest()
        self.assertEqual(_kdf(ck, ikm), (o1, o2))

    def test_low_order_points_refused_in_config(self):
        for h in LOW_ORDER_PUBLIC:
            with self.subTest(h=h[:8]):
                raw = bytes.fromhex(h)
                self.assertTrue(_is_low_order(raw))
                with self.assertRaises(RuntimeError):
                    public_key_from_b64(encode_key(raw))
                with self.assertRaises(ValueError):
                    Node(X25519PrivateKey.generate()).add_peer(raw, A_ADDR)

    def test_valid_public_keys_still_accepted(self):
        for _ in range(20):
            _, pub = generate_keypair()
            self.assertFalse(_is_low_order(pub))
            self.assertEqual(public_key_from_b64(encode_key(pub)), pub)


# ================================================================ hardening (kept)
class HardenedHandshakeTests(unittest.TestCase):
    def test_all_zero_shared_secret_rejected(self):
        # Aumasson ch.12: a zero output from a low-order peer point must never become a key.
        with self.assertRaises(HandshakeError):
            _dh(X25519PrivateKey.generate(), bytes(32))

    def test_low_order_peer_public_key_rejected_by_responder(self):
        """A valid mac1 over an all-zero ephemeral key must still be refused by the DH check."""
        b = Node(X25519PrivateKey.generate(), b"")
        msg = forge_init(b.pub, eph=bytes(32))
        with self.assertRaises(HandshakeError):
            consume_initiation(b._priv, b.pub, b.kem_pub, b._kem_priv, msg)
        self.assertEqual(b.handle(msg, A_ADDR).send, [])

    def test_auth_with_correct_transcript_is_accepted(self):
        """Control case: an honest INIT decrypts, so the rejections below come from the edits."""
        a, b, pa, init = unfinished()
        info = consume_initiation(b._priv, b.pub, b.kem_pub, b._kem_priv, init)
        self.assertEqual(info.peer_pub, a.pub)
        info = finish_initiation(info, b._priv, b"")
        self.assertEqual(len(info.timestamp), 12)            # TAI64N

    def test_bad_transcript_mac_rejected(self):
        """The hash chain covers every field. A changed ephemeral or timestamp fails the AEAD even
        with a fresh, valid mac1."""
        a, b, pa, init = unfinished()
        bad_eph = bytearray(init)
        bad_eph[8] ^= 0x01
        with self.assertRaises(HandshakeError):
            consume_initiation(b._priv, b.pub, b.kem_pub, b._kem_priv, remac1(bytes(bad_eph), INIT_MAC1, b.pub, b""))
        bad_ts = bytearray(init)
        bad_ts[INIT_MAC1 - 10] ^= 0x01                      # inside the encrypted timestamp
        info = consume_initiation(b._priv, b.pub, b.kem_pub, b._kem_priv, remac1(bytes(bad_ts), INIT_MAC1, b.pub, b""))
        with self.assertRaises(HandshakeError):
            finish_initiation(info, b._priv, b"")

    def test_reflected_key_confirmation_tag_rejected(self):
        """A RESP whose type byte is rewritten to INIT is rejected by the type and length check."""
        a, b, pa, init = unfinished()
        (resp, _), = b.handle(init, A_ADDR).send
        as_init = bytes([MSG_INIT]) + resp[1:]
        with self.assertRaises(HandshakeError):
            consume_initiation(b._priv, b.pub, b.kem_pub, b._kem_priv, as_init)
        with self.assertRaises(HandshakeError):
            consume_response(pa.pending, as_init)

    def test_reflected_handshake_messages_rejected(self):
        a, b, pa, init = unfinished()
        (resp, _), = b.handle(init, A_ADDR).send
        with self.assertRaises(HandshakeError):      # INIT reflected to the initiator
            consume_response(pa.pending, init)
        with self.assertRaises(HandshakeError):      # RESP reflected to the responder
            consume_initiation(b._priv, b.pub, b.kem_pub, b._kem_priv, resp)

    def test_child_keys_distinct_per_direction_and_purpose(self):
        """Transport keys differ per direction. Cookie keys differ per salt."""
        k1, k2 = _transport_keys(os.urandom(32))
        self.assertEqual((len(k1), len(k2)), (32, 32))
        self.assertNotEqual(k1, k2)
        pub = os.urandom(32)
        self.assertNotEqual(_cookie_key(pub, os.urandom(32)), _cookie_key(pub, os.urandom(32)))


class HardenedReplayTests(unittest.TestCase):
    def test_window_edge_after_large_jump(self):
        w = ReplayWindow()
        w.update(1)
        w.update(200)                          # shift >= WINDOW: old bits all cleared
        self.assertIsNone(w.check(199))        # distance 1, never seen: fresh
        self.assertEqual(w.check(1), "out of window")
        self.assertIsNone(w.check(200 - (WINDOW - 1)))             # distance 63: inside
        self.assertEqual(w.check(200 - WINDOW), "out of window")   # distance 64: outside

    def test_update_never_sets_bits_outside_window(self):
        w = ReplayWindow()
        w.top = 100
        w.update(1)                            # distance 99: outside; must be a no-op
        self.assertEqual(w.bitmap, 0)


class HardenedServerTests(unittest.TestCase):
    def test_authenticated_empty_inner_does_not_crash_server(self):
        """Test kept from the earlier prototype, updated: an empty inner datagram is now a valid
        keepalive (V-E), so the non-IPv4 check is exercised with a 5-byte inner datagram.
        The server must not crash, and must go on handling packets."""
        a = Node(X25519PrivateKey.generate())
        b = Node(X25519PrivateKey.generate())
        pa = a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
        b.add_peer(a.pub, kem_pub=a.kem_pub).spd = list(PROTECT_ALL)   # the server echoes through its peer's SPD
        pa.spd = list(PROTECT_ALL)
        (init, _), = a.initiate(pa)
        logs = []

        def on_send(data, addr):
            if addr == A_ADDR and data[0] == MSG_RESP:
                act = a.handle(data, B_ADDR)
                for pkt, _dst in act.send:
                    sock.inbox.append((pkt, A_ADDR))                       # confirmation
                sess = pa.current
                sock.inbox.append((seal_data(sess, b"\x00" * 5, time.monotonic()), A_ADDR))   # not IPv4
                sock.inbox.append((seal_data(sess, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"ok"),
                                             time.monotonic()), A_ADDR))

        sock = FakeSock([(init, A_ADDR)], on_send)
        serve(sock, b, echo=True, out=logs.append)                       # must return normally
        self.assertTrue(any("dropped packet" in s and "not IPv4" in s for s in logs), logs)
        self.assertTrue(any(s.startswith("<- decrypted") for s in logs), logs)

    def test_server_survives_malformed_init_then_auth(self):
        """Malformed INIT and RESP bytes must neither crash the server nor produce any reply."""
        b = Node(X25519PrivateKey.generate())
        b.add_peer(X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw))
        bad_init = bytes([MSG_INIT, 0, 0, 0]) + bytes(10)
        bad_resp = bytes([MSG_RESP, 0, 0, 0]) + bytes(52)
        sock = FakeSock([(bad_init, B_ADDR), (bad_resp, B_ADDR)])
        serve(sock, b, out=lambda s: None)                    # must return normally
        self.assertEqual(sock.sent, [])

    def test_unauthenticated_floods_keep_no_state(self):
        """Changed on purpose: the old 'pending cap' is replaced by 'no state before
        authentication' (V-A). Forged INITs (valid mac1, bad AEAD) and INITs from unknown keys
        get no reply and create no session or pending entry."""
        b = Node(X25519PrivateKey.generate())
        known = Node(X25519PrivateKey.generate())
        b.add_peer(known.pub, kem_pub=known.kem_pub)
        # Valid mac1 but bad AEAD. 200 of these in one second put the responder under load, so
        # the only allowed reply is a cookie reply (V-C). No response and no state may result.
        inbox = [(forge_init(b.pub), (f"198.51.100.{i % 250}", 20000 + i)) for i in range(200)]
        for i in range(100):
            stranger = X25519PrivateKey.generate()
            stranger_pub = stranger.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            tmp = Node(stranger)
            tp = tmp.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
            (init, _), = tmp.initiate(tp)
            inbox.append((init, (f"203.0.113.{i % 250}", 30000 + i)))
        sock = FakeSock(inbox)
        serve(sock, b, out=lambda s: None)
        self.assertTrue(all(data[0] == MSG_COOKIE for data, _ in sock.sent))
        self.assertEqual(b.sessions, {})
        self.assertEqual(b.pending, {})

    def test_oversized_datagrams_dropped_before_parsing(self):
        b = Node(X25519PrivateKey.generate())
        b.add_peer(X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw))
        logs = []
        big_ike = bytes([MSG_INIT, 0, 0, 0]) + bytes(MAX_ESP)              # > MAX_ESP
        big_esp = struct.pack("<I", 0x01020304) + bytes(MAX_ESP)
        sock = FakeSock([(big_ike, B_ADDR), (big_esp, B_ADDR)])
        serve(sock, b, out=logs.append)
        self.assertEqual(sock.sent, [])
        self.assertEqual(logs, [])


class OperationsOutputTests(unittest.TestCase):
    """What the endpoint prints. The payload stays out of output unless --show-payload is set,
    and the rejection counter counts refused inbound datagrams without keeping their lines."""

    def test_rejection_counter_counts_only_inbound_refusals(self):
        lines = [
            "tunnel up with ('127.0.0.1', 1)",
            "handshake from ('127.0.0.1', 1) accepted; response sent, waiting for first data",
            "under load: cookie reply to ('127.0.0.1', 1)",
            "dropped tun packet: no peer with a session for this destination",
            "dropped packet from ('127.0.0.1', 1): unknown index",
            "dropped inner datagram from ('127.0.0.1', 1): not IPv4",
            "handshake from ('127.0.0.1', 1) rejected: handshake failed",
            "<- decrypted 10.8.0.2 -> 10.8.0.1 proto=253 len=20",
        ]
        seen = []
        counter = RejectCounter(seen.append)
        for line in lines:
            counter(line)
        self.assertEqual(counter.count, 3)
        self.assertEqual(seen, lines)          # every line still reaches the sink unchanged

    def test_flood_of_unknown_index_datagrams_is_counted(self):
        b = Node(X25519PrivateKey.generate())
        b.add_peer(X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw))
        junk = struct.pack("<BBxxI", MSG_DATA, 2, 0x0BADBEEF) + bytes(40)
        counter = RejectCounter(lambda s: None)
        serve(FakeSock([(junk, B_ADDR)] * 5), b, out=counter)
        self.assertEqual(counter.count, 5)

    def test_handshake_refusal_log_gives_reason_without_key(self):
        """ch.15: the log says why an INIT was refused (unknown key), with the source address and
        no key material. Nothing is sent back, so there is no wire oracle."""
        b = Node(X25519PrivateKey.generate(), clock=lambda: 100.0)
        stranger = Node(X25519PrivateKey.generate(), clock=lambda: 100.0)
        tp = stranger.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
        (init, _), = stranger.initiate(tp, 100.0)
        act = b.handle(init, A_ADDR, 100.0)
        self.assertEqual(act.send, [])
        self.assertEqual(act.events, [f"handshake from {A_ADDR} rejected: unknown peer key"])
        self.assertNotIn(encode_key(stranger.pub), act.events[0])
        self.assertNotIn(stranger.pub.hex(), act.events[0])

    def test_refusal_log_is_rate_limited_but_still_counted(self):
        """ch.10 bounded output: a flood of unknown-index datagrams prints at most LOG_BURST lines
        at once, then LOG_RATE per second. Every refusal is still counted (printed + unlogged)."""
        b = Node(X25519PrivateKey.generate(), clock=lambda: 100.0)
        b.add_peer(X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw))
        junk = struct.pack("<BBxxI", MSG_DATA, 2, 0x0BADBEEF) + bytes(40)
        printed = []
        for _ in range(500):
            printed += b.handle(junk, B_ADDR, 100.0).events
        self.assertEqual(len(printed), LOG_BURST)
        self.assertEqual(b.refusals_unlogged, 500 - LOG_BURST)
        # One second later the budget has refilled by LOG_RATE tokens.
        more = []
        for _ in range(50):
            more += b.handle(junk, B_ADDR, 101.0).events
        self.assertEqual(len(more), int(LOG_RATE))
        self.assertEqual(len(printed) + len(more) + b.refusals_unlogged, 550)

    def test_payload_printed_only_with_show_payload(self):
        marker = "SECRET-PAYLOAD-123"
        a, b = pair()
        pkt = seal_data(a.peers[b.pub].current,
                        build_ipv4("10.8.0.2", "10.8.0.1", 253, marker.encode()), time.monotonic())
        logs = []
        serve(FakeSock([(pkt, A_ADDR)]), b, echo=False, show_payload=False, out=logs.append)
        self.assertTrue(any(s.startswith("<- decrypted") for s in logs), logs)
        self.assertFalse(any(marker in s for s in logs), logs)

        a, b = pair()
        pkt = seal_data(a.peers[b.pub].current,
                        build_ipv4("10.8.0.2", "10.8.0.1", 253, marker.encode()), time.monotonic())
        logs = []
        serve(FakeSock([(pkt, A_ADDR)]), b, echo=False, show_payload=True, out=logs.append)
        self.assertTrue(any(marker in s for s in logs), logs)


class ResetTests(unittest.TestCase):
    """Windows: after the server sends to a closed port, the next recvfrom raises
    ConnectionResetError (WSAECONNRESET). Reproduced on Windows 11 (udp_reset_check). The server
    must keep serving, as the client already does in vpn_client._recv_from."""

    def test_serve_survives_reset_and_handles_next_datagram(self):
        b = Node(X25519PrivateKey.generate())
        a = Node(X25519PrivateKey.generate())
        b.add_peer(a.pub, kem_pub=a.kem_pub)
        (init, _), = a.initiate(a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub))
        sock = FakeSock([ConnectionResetError(10054, "reset"), (init, A_ADDR)])
        serve(sock, b, out=lambda s: None)                  # must not raise
        self.assertTrue(any(data[0] == MSG_RESP for data, _ in sock.sent), sock.sent)

    def test_serve_tun_survives_reset(self):
        class ResetOnceSocket(socket.socket):
            """A real UDP socket (so select() works) whose first recvfrom reports a reset."""
            reset_done = False

            def recvfrom(self, n, *args):
                if not self.reset_done:
                    self.reset_done = True
                    raise ConnectionResetError(10054, "reset")
                return super().recvfrom(n, *args)

        class IdleTun(TunDevice):
            def __init__(self):
                self._r, self._w = socket.socketpair()      # nothing is ever written to it

            def fileno(self):
                return self._r.fileno()

            def read_packet(self):
                raise AssertionError("no host packet expected")

            def write_packet(self, pkt):
                raise AssertionError("no inner packet expected")

            def close(self):
                self._r.close()
                self._w.close()

        b = Node(X25519PrivateKey.generate())
        b.add_peer(X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw))
        sock = ResetOnceSocket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.sendto(b"\x04" + bytes(15), sock.getsockname())   # wakes select; junk is ignored
        tun = IdleTun()
        try:
            serve_tun(sock, b, tun, idle_timeout=0.3, out=lambda s: None, tick=0.05)  # must return
        finally:
            sock.close()
            peer.close()
            tun.close()
        self.assertTrue(sock.reset_done)


class HardenedClientTests(unittest.TestCase):
    def test_receive_has_overall_deadline(self):
        class Flood(FakeSock):
            def recvfrom(self, n):                        # never idle: always another source
                return (b"x", ("203.0.113.9", 1))
        start = time.monotonic()
        with self.assertRaises(socket.timeout):
            _recv_from(Flood(), B_ADDR, 0.2)
        self.assertLess(time.monotonic() - start, 5.0)

    def test_stale_esp_packet_is_skipped_during_handshake(self):
        esp_stale = bytes([MSG_DATA, 0, 0, 0]) + struct.pack("<I", 1234) + bytes(40)
        resp = bytes([MSG_RESP, 0, 0, 0]) + bytes(88)
        sock = FakeSock([(esp_stale, B_ADDR), (resp, B_ADDR)])
        self.assertEqual(_recv_from(sock, B_ADDR, 1.0, want=lambda d: d[0] == MSG_RESP), resp)

    def test_oversized_reply_skipped(self):
        resp = bytes([MSG_RESP, 0, 0, 0]) + bytes(88)
        sock = FakeSock([(bytes([MSG_RESP, 0, 0, 0]) + bytes(MAX_ESP), B_ADDR), (resp, B_ADDR)])
        self.assertEqual(_recv_from(sock, B_ADDR, 1.0, want=lambda d: d[0] == MSG_RESP), resp)


# ================================================================ WireGuard items
class InitiationTests(unittest.TestCase):
    """Items 3 to 5: identity hiding, timestamps, mac1/mac2 checks."""

    def test_identity_hidden_on_wire(self):
        a, b, pa, init = unfinished()
        self.assertNotIn(a.pub, init)                  # the initiator's static key is encrypted
        (resp, _), = b.handle(init, A_ADDR).send
        self.assertNotIn(a.pub, resp)
        self.assertNotIn(b.pub, init)

    def test_replayed_initiation_rejected(self):
        a, b, pa, init = unfinished()
        self.assertEqual(len(b.handle(init, A_ADDR).send), 1)
        act = b.handle(init, A_ADDR)                   # same bytes again
        self.assertEqual(act.send, [])
        self.assertTrue(any("stale or replayed timestamp" in e for e in act.events), act.events)

    def test_old_timestamp_rejected(self):
        """A valid INIT whose timestamp is not greater than the last one is refused (V-A)."""
        a, b, pa, _ = unfinished()
        now_ns = time.time_ns()
        fresh, _ = make_initiation(a._priv, a.pub, a._kem_priv, b.pub, b.kem_pub, b"", 77, _tai64n(now_ns))
        self.assertEqual(len(b.handle(fresh, A_ADDR).send), 1)
        old, _ = make_initiation(a._priv, a.pub, a._kem_priv, b.pub, b.kem_pub, b"", 78, _tai64n(now_ns - 60 * 10**9))
        self.assertEqual(b.handle(old, A_ADDR).send, [])

    def test_timestamps_strictly_increase_per_peer(self):
        p = Peer(bytes(31) + b"\x01", None, None)
        t = _tai64n(time.time_ns())
        first = p.next_timestamp(t)
        second = p.next_timestamp(t)                  # same clock reading: must still increase
        self.assertGreater(second, first)
        self.assertEqual(len(first), 12)

    def test_mac1_checked_silently(self):
        a, b, pa, init = unfinished()
        bad = bytearray(init)
        bad[120] ^= 0x01                               # inside mac1, no recomputation
        act = b.handle(bytes(bad), A_ADDR)
        self.assertEqual(act.send, [])
        self.assertEqual(act.events, [])                # no reply and nothing logged on the wire
        self.assertEqual(b.sessions, {})

    def test_mac2_checked_under_load(self):
        """Under load, an INIT with no valid mac2 gets a cookie reply and no DH work (V-C)."""
        b = Node(X25519PrivateKey.generate(), load_threshold=0)
        b.add_peer(X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw))
        msg = forge_init(b.pub)                         # zero mac2
        with mock.patch("vpn_node.consume_initiation") as dh:
            act = b.handle(msg, A_ADDR)
        self.assertEqual(dh.call_count, 0)
        self.assertEqual(len(act.send), 1)
        self.assertEqual(act.send[0][0][0], MSG_COOKIE)
        self.assertEqual(act.send[0][1], A_ADDR)


class CookieTests(unittest.TestCase):
    """Item 5: cookie reply works, is encrypted, and is bound to the source address and the INIT."""

    def setUp(self):
        self.clk = FakeClock(1000.0)
        self.a = Node(X25519PrivateKey.generate(), clock=self.clk, rand=lambda: 0.5)   # no retry jitter
        self.b = Node(X25519PrivateKey.generate(), clock=self.clk, load_threshold=0, rand=lambda: 0.5)
        self.pa = self.a.add_peer(self.b.pub, B_ADDR, kem_pub=self.b.kem_pub)
        self.b.add_peer(self.a.pub, kem_pub=self.a.kem_pub)

    def _cookie_from_b(self):
        (init, _), = self.a.initiate(self.pa, self.clk.t)
        (cookie, dst), = self.b.handle(init, A_ADDR, self.clk.t).send
        self.assertEqual(cookie[0], MSG_COOKIE)
        self.assertEqual(len(cookie), 72)
        self.assertEqual(dst, A_ADDR)
        self.assertEqual(self.b.sessions, {})            # no state from the cookie path
        self.a.handle(cookie, B_ADDR, self.clk.t)
        self.assertIsNotNone(self.pa.cookie)

    def test_cookie_reply_roundtrip(self):
        self._cookie_from_b()
        self.clk.t += 1
        self.assertEqual(self.a.poll(self.clk.t), [])    # no immediate resend (V-F)
        self.clk.t += 4                                  # REKEY_TIMEOUT after the first INIT
        (init2, dst), = self.a.poll(self.clk.t)
        self.assertNotEqual(init2[INIT_LEN - 16:INIT_LEN], bytes(16))   # mac2 now present
        self.assertEqual(init2[0], MSG_INIT)
        act = self.b.handle(init2, A_ADDR, self.clk.t)   # valid mac2 under load: accepted
        self.assertEqual(act.send[0][0][0], MSG_RESP)
        self.a.handle(act.send[0][0], B_ADDR, self.clk.t)
        self.assertIsNotNone(self.pa.current)

    def test_cookie_is_bound_to_source_address(self):
        """A cookie for 127.0.0.1 is useless from another address (mac2 is keyed by the cookie)."""
        self._cookie_from_b()
        self.clk.t += 5
        (init2, _), = self.a.poll(self.clk.t)
        act = self.b.handle(init2, ("203.0.113.7", 1), self.clk.t)
        self.assertEqual(act.send[0][0][0], MSG_COOKIE)  # challenged again, no DH state
        self.assertEqual(self.b.sessions, {})
        self.assertEqual(self.b.handle(init2, A_ADDR, self.clk.t).send[0][0][0], MSG_RESP)

    def test_cookie_reply_bound_to_initiation(self):
        """A cookie reply made for a different mac1 (the AEAD associated data) is ignored."""
        self.a.initiate(self.pa, self.clk.t)
        secret = self.b._cookie_secrets(self.clk.t)[0]
        forged = make_cookie_reply(self.b.pub, secret, A_ADDR, bytes(16), self.pa.pending.sender)
        self.a.handle(forged, B_ADDR, self.clk.t)
        self.assertIsNone(self.pa.cookie)

    def test_cookie_secret_rotates(self):
        s0 = self.b._cookie_secrets(self.clk.t)
        s1 = self.b._cookie_secrets(self.clk.t + 121)
        self.assertNotEqual(s0[0], s1[0])
        self.assertEqual(s1[1], s0[0])                   # the previous secret still validates


class RoamingTests(unittest.TestCase):
    """Item 6: the endpoint follows the latest authenticated packet (II-A)."""

    def test_roaming_updates_endpoint(self):
        a, b = pair()
        pa, pb = a.peers[b.pub], b.peers[a.pub]
        wire, _ = a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"one"))
        new_addr = ("127.0.0.1", 40001)
        self.assertEqual(b.handle(wire, new_addr).inner, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"one"))
        self.assertEqual(pb.endpoint, new_addr)
        wire, dst = b.send(pb, build_ipv4("10.8.0.1", "10.8.0.2", 253, b"two"))
        self.assertEqual(dst, new_addr)                  # replies go to the new port

    def test_forged_or_replayed_packet_does_not_roam(self):
        a, b = pair()
        pa, pb = a.peers[b.pub], b.peers[a.pub]
        wire, _ = a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x"))
        forged = bytearray(wire)
        forged[-1] ^= 0x01
        b.handle(bytes(forged), ("203.0.113.9", 9))
        self.assertEqual(pb.endpoint, A_ADDR)
        b.handle(wire, ("203.0.113.10", 10))            # first delivery from A's real packet
        self.assertEqual(pb.endpoint, ("203.0.113.10", 10))
        b.handle(wire, ("203.0.113.11", 11))            # replay from a third address
        self.assertEqual(pb.endpoint, ("203.0.113.10", 10))


class KeepaliveTests(unittest.TestCase):
    """Item 7: an empty authenticated packet after an idle period, with a configurable period."""

    def test_keepalive_sent_after_idle_period(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pa, pb = a.peers[b.pub], b.peers[a.pub]
        wire, _ = a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"ping"), clk.t)
        b.handle(wire, A_ADDR, clk.t)
        self.assertEqual(b.poll(clk.t + 5), [])          # not yet idle long enough
        (ka, dst), = b.poll(clk.t + 10)
        self.assertEqual(dst, A_ADDR)
        act = a.handle(ka, B_ADDR, clk.t + 10)
        self.assertEqual(act.inner, b"")                 # a zero-length inner datagram
        self.assertEqual(act.events, [])

    def test_keepalive_period_is_configurable(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pa, pb = a.peers[b.pub], b.peers[a.pub]
        pb.keepalive = 3
        wire, _ = a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"ping"), clk.t)
        b.handle(wire, A_ADDR, clk.t)
        self.assertEqual(len(b.poll(clk.t + 3)), 1)

    def test_no_keepalive_without_inbound_data(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        self.assertEqual(b.poll(clk.t + 100), [])

    def test_keepalive_disabled(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pb = b.peers[a.pub]
        pb.keepalive = None
        wire, _ = a.send(a.peers[b.pub], build_ipv4("10.8.0.2", "10.8.0.1", 253, b"ping"), clk.t)
        b.handle(wire, A_ADDR, clk.t)
        self.assertEqual(b.poll(clk.t + 100), [])


class RekeyTests(unittest.TestCase):
    """Item 8: rekey by time and by message count, from either side."""

    def test_message_limit_is_the_stricter_bound(self):
        self.assertEqual(REKEY_AFTER_MESSAGES, SEQ_MAX - REKEY_MARGIN)
        self.assertLess(REKEY_AFTER_MESSAGES, 2**60)     # the paper's example is looser

    def test_rekey_by_time(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pa = a.peers[b.pub]
        old = pa.current
        wire, _ = a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"one"), clk.t)
        b.handle(wire, A_ADDR, clk.t)
        clk.t += 121
        self.assertEqual(a.poll(clk.t), [])              # due, but the INIT waits a random delay (2.8.1)
        clk.t += REKEY_JITTER_MAX
        (init, _), = a.poll(clk.t)                       # the delay has passed: a new INIT
        (resp, _), = b.handle(init, A_ADDR, clk.t).send
        confirm = a.handle(resp, B_ADDR, clk.t).send
        for pkt, dst in confirm:
            b.handle(pkt, A_ADDR, clk.t)
        self.assertIsNot(pa.current, old)
        self.assertIs(pa.previous, old)                  # in-flight packets still decrypt
        wire, _ = a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"two"), clk.t)
        self.assertEqual(b.handle(wire, A_ADDR, clk.t).inner, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"two"))

    def test_rekey_by_message_count(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pa = a.peers[b.pub]
        pa.current.limit = pa.current.send_counter + 3
        for _ in range(3):
            a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x"), clk.t)
        with self.assertRaises(RekeyRequired):
            a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x"), clk.t)
        self.assertEqual(a.poll(clk.t + 6), [])          # due, waiting for the random delay
        (init, _), = a.poll(clk.t + 6 + REKEY_JITTER_MAX)
        self.assertEqual(init[0], MSG_INIT)

    def test_responder_can_initiate_rekey(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pb = b.peers[a.pub]
        pb.current.limit = 1
        wire, _ = b.send(pb, build_ipv4("10.8.0.1", "10.8.0.2", 253, b"from b"), clk.t)
        a.handle(wire, B_ADDR, clk.t)
        clk.t += 1
        self.assertEqual(b.poll(clk.t), [])              # due, waiting for the random delay
        clk.t += REKEY_JITTER_MAX
        (init, _), = b.poll(clk.t)                       # the responder starts the rekey
        (resp, _), = a.handle(init, B_ADDR, clk.t).send
        for pkt, _dst in b.handle(resp, A_ADDR, clk.t).send:
            a.handle(pkt, B_ADDR, clk.t)
        wire, _ = b.send(pb, build_ipv4("10.8.0.1", "10.8.0.2", 253, b"after"), clk.t)
        self.assertEqual(a.handle(wire, B_ADDR, clk.t).inner,
                         build_ipv4("10.8.0.1", "10.8.0.2", 253, b"after"))

    def test_rekey_is_rate_limited(self):
        clk = FakeClock(1000.0)
        a, b, pa, _ = unfinished(clock=clk)
        self.assertEqual(a.initiate(pa, clk.t + 1), [])
        self.assertEqual(len(a.initiate(pa, clk.t + 6)), 1)


class KeyHandlingTests(unittest.TestCase):
    """Item 1: keys come from a file or an env var, never from source."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in (KEY_ENV, KEY_FILE_ENV)}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_generated_keys_are_base64_32_bytes(self):
        priv, pub = generate_keypair()
        self.assertEqual(len(encode_key(priv)), 44)
        self.assertEqual(public_key_from_b64(encode_key(pub)), pub)
        private_key_from_b64(encode_key(priv))

    def test_key_from_env_var(self):
        priv, pub = generate_keypair()
        os.environ[KEY_ENV] = encode_key(priv)
        loaded = load_static_private()
        self.assertEqual(loaded.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), pub)

    def test_key_from_file(self):
        priv, pub = generate_keypair()
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(encode_key(priv) + "\n")
            loaded = load_static_private(path)
            self.assertEqual(loaded.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), pub)
        finally:
            os.remove(path)

    def test_missing_key_is_reported_without_value(self):
        with self.assertRaises(RuntimeError) as cm:
            load_static_private()
        self.assertIn(KEY_ENV, str(cm.exception))

    def test_bad_key_error_does_not_echo_value(self):
        bad = "QUFB" * 10 + "A"
        with self.assertRaises(RuntimeError) as cm:
            private_key_from_b64(bad)
        self.assertNotIn(bad, str(cm.exception))

    def test_static_keys_are_not_in_source(self):
        """The shipped modules must not contain a base64 key literal (44 characters ending in '=')."""
        import re
        here = os.path.dirname(os.path.abspath(__file__))
        for name in ("vpn_constants.py", "vpn_errors.py", "vpn_crypto.py", "vpn_keyfiles.py", "vpn_state.py",
                     "vpn_handshake.py", "vpn_ip.py", "vpn_transport.py", "vpn_node.py", "vpn_tun.py",
                     "vpn_server.py", "vpn_client.py", "vpn_keygen.py"):
            with open(os.path.join(here, name), encoding="utf-8") as f:
                self.assertIsNone(re.search(r"[A-Za-z0-9+/]{43}=", f.read()), name)


# ================================================================ revocation (KEY_LIFECYCLE.md)
class RevocationTests(unittest.TestCase):
    """A removed peer's live session and handshake attempts must stop working at once."""

    def test_removed_peer_session_is_dropped(self):
        clk = FakeClock()
        a, b = pair(clock=clk)
        wire, _ = a.send(a.peers[b.pub], build_ipv4("10.8.0.2", "10.8.0.1", 253, b"before"), clk.t)
        self.assertEqual(b.handle(wire, A_ADDR, clk.t).inner[-6:], b"before")
        b.remove_peer(a.pub)
        self.assertNotIn(a.pub, b.peers)
        self.assertEqual(b.sessions, {})
        wire2, _ = a.send(a.peers[b.pub], build_ipv4("10.8.0.2", "10.8.0.1", 253, b"after"), clk.t)
        act = b.handle(wire2, A_ADDR, clk.t)
        self.assertIsNone(act.inner)
        self.assertIn("dropped packet from", act.events[0])
        self.assertIn("unknown index", act.events[0])

    def test_removed_peer_cannot_handshake_again(self):
        clk = FakeClock()
        a, b = pair(clock=clk)
        b.remove_peer(a.pub)
        clk.t += 10.0                      # past REKEY_TIMEOUT, so a new INIT is allowed
        init = a.initiate(a.peers[b.pub], clk.t)
        self.assertEqual(len(init), 1)
        act = b.handle(init[0][0], A_ADDR, clk.t)
        self.assertEqual(act.send, [])     # unknown key: no response, no state
        self.assertEqual(b.sessions, {})
        self.assertEqual(b.pending, {})

    def test_remove_pending_handshake_and_unknown_key_is_safe(self):
        clk = FakeClock()
        a, b = unfinished(clock=clk)[:2]
        pa = a.peers[b.pub]
        b.remove_peer(b"\x01" * 32)        # never configured: no error
        a.remove_peer(b.pub)
        self.assertIsNone(a.peers.get(b.pub))
        self.assertIsNone(pa.pending)      # the pending INIT is forgotten too
        self.assertEqual(a.pending, {})

    def test_other_peers_keep_their_sessions(self):
        clk = FakeClock()
        a, b = pair(clock=clk)
        c = Node(X25519PrivateKey.generate(), b"", clk)
        b.add_peer(c.pub, None, kem_pub=c.kem_pub)
        b.remove_peer(c.pub)
        wire, _ = a.send(a.peers[b.pub], build_ipv4("10.8.0.2", "10.8.0.1", 253, b"still"), clk.t)
        self.assertEqual(b.handle(wire, A_ADDR, clk.t).inner[-5:], b"still")


# ================================================================ side channels (SIDE_CHANNEL_REVIEW.md)
class _FixedExchangeKey:
    """Stands in for X25519PrivateKey so _dh sees a chosen shared-secret output."""
    def __init__(self, out):
        self._out = out

    def exchange(self, peer):
        return self._out


class SideChannelCompareTests(unittest.TestCase):
    """Functional checks only: each comparison changed for side-channel reasons still rejects a
    wrong value. These do not test timing; that is not reliable in Python."""

    def test_dh_rejects_all_zero_output(self):
        with self.assertRaises(HandshakeError):
            _dh(_FixedExchangeKey(bytes(32)), bytes(32))

    def test_dh_accepts_nonzero_output(self):
        out = bytes(range(1, 33))
        self.assertEqual(_dh(_FixedExchangeKey(out), bytes(32)), out)

    def test_mac1_rejects_wrong_tag(self):
        priv = X25519PrivateKey.generate()
        pub = _pub_raw(priv)
        peer_pub = _pub_raw(X25519PrivateKey.generate())
        msg, _ = make_initiation(priv, pub, mlkem.MLKEM768PrivateKey.generate(), peer_pub, mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw(), b"", 7, bytes(12))
        self.assertTrue(_check_mac1(msg, INIT_MAC1, peer_pub))
        bad = bytearray(msg)
        bad[INIT_MAC1] ^= 0x01
        self.assertFalse(_check_mac1(bytes(bad), INIT_MAC1, peer_pub))

    def test_mac2_rejects_wrong_tag_and_wrong_address(self):
        priv = X25519PrivateKey.generate()
        pub = _pub_raw(priv)
        peer_pub = _pub_raw(X25519PrivateKey.generate())
        msg, _ = make_initiation(priv, pub, mlkem.MLKEM768PrivateKey.generate(), peer_pub, mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw(), b"", 7, bytes(12))
        off = INIT_MAC1
        secret = os.urandom(32)
        addr = ("192.0.2.10", 51820)
        body = msg[:off + TAG_LEN]
        good = body + _mac(_cookie_tau(secret, addr), body)
        self.assertTrue(_check_mac2(good, off, [secret], addr))
        bad = bytearray(good)
        bad[-1] ^= 0x01
        self.assertFalse(_check_mac2(bytes(bad), off, [secret], addr))
        self.assertFalse(_check_mac2(good, off, [secret], ("192.0.2.11", 51820)))


class ProtocolAttackTests(unittest.TestCase):
    """Protocol attack classes from Anderson ch. 4 and ch. 21, each with a test that fails if the
    defence is removed. See SECURITY_ENGINEERING_REVIEW.md for the mapping."""

    def test_keygen_warns_against_key_reuse(self):
        """Chosen protocol attacks (ch. 4): the operator is told not to reuse the key pair elsewhere."""
        import contextlib
        import io
        import vpn_keygen
        err = io.StringIO()
        with mock.patch("sys.argv", ["vpn_keygen.py", "--stdout"]), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err):
            vpn_keygen.main()
        self.assertIn("this tunnel only", err.getvalue())

    def test_keygen_without_out_or_stdout_prints_no_private_key(self):
        """Open issue 25: the private key is never printed unless --stdout is given."""
        import contextlib
        import io
        import vpn_keygen
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.argv", ["vpn_keygen.py"]), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            vpn_keygen.main()
        self.assertEqual(cm.exception.code, 2)                  # argparse usage error
        self.assertEqual(out.getvalue(), "")
        self.assertIn("--out", err.getvalue())

    def test_superseded_response_is_ignored_and_fresh_one_completes(self):
        """Parallel handshakes from one initiator. RESP1 answers INIT1 after INIT2 is pending. It
        is ignored (sender index), and RESP2 completes the tunnel. The responder then promotes
        session 2 on the confirmation, so the two runs never mix (ch. 4 interleaving)."""
        clk = FakeClock(1000.0)
        a = Node(X25519PrivateKey.generate(), b"", clk)
        b = Node(X25519PrivateKey.generate(), b"", clk)
        pa = a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
        pb = b.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
        (init1, _), = a.initiate(pa, 1000.0)
        (init2, _), = a.initiate(pa, 1006.0)            # INIT1 is dropped as pending
        resp1 = b.handle(init1, A_ADDR, 1000.0).send[0][0]
        resp2 = b.handle(init2, A_ADDR, 1006.0).send[0][0]
        with self.assertRaises(HandshakeError):          # RESP1 does not fit INIT2's state
            consume_response(pa.pending, resp1)
        act = a.handle(resp1, B_ADDR, 1006.0)
        self.assertEqual(act.send, [])
        self.assertIsNone(pa.current)
        act = a.handle(resp2, B_ADDR, 1006.0)
        self.assertEqual(len(act.send), 1)               # confirmation keepalive
        self.assertIsNotNone(pa.current)
        b.handle(act.send[0][0], A_ADDR, 1006.0)
        self.assertEqual(pb.current.remote_index, pa.current.local_index)   # session 2 promoted
        self.assertIsNone(pb.next)

    def test_replayed_response_after_tunnel_up_changes_nothing(self):
        a, b, pa, init = unfinished()
        (resp, _), = b.handle(init, A_ADDR).send
        a.handle(resp, B_ADDR)
        sess = pa.current
        self.assertIsNotNone(sess)
        act = a.handle(resp, B_ADDR)                      # same RESP again
        self.assertEqual(act.send, [])
        self.assertIs(pa.current, sess)
        self.assertIsNone(pa.next)

    def test_handshake_messages_retyped_as_another_type_are_dropped(self):
        """Type confusion (ch. 4): each message is retyped to every other type. None may be
        accepted, and no session or data is produced."""
        a, b, pa, init = unfinished()
        (resp, _), = b.handle(init, A_ADDR).send
        before = dict(b.sessions)                        # the one pending session from the INIT above
        clk = FakeClock(1000.0)
        probe = Node(X25519PrivateKey.generate(), b"", clk, load_threshold=0)
        probe.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
        init_p = make_initiation(a._priv, a.pub, a._kem_priv, probe.pub, probe.kem_pub, b"", 5, _tai64n(time.time_ns()))[0]
        (cookie, _), = probe.handle(init_p, A_ADDR, 1000.0).send
        for msg, own in ((init, MSG_INIT), (resp, MSG_RESP), (cookie, MSG_COOKIE)):
            for t in (MSG_INIT, MSG_RESP, MSG_COOKIE, MSG_DATA):
                if t == own:
                    continue
                retyped = bytes([t]) + msg[1:]
                act = b.handle(retyped, A_ADDR)
                act_a = a.handle(retyped, B_ADDR)
                self.assertEqual(act.send, [], (own, t))
                self.assertEqual(act_a.send, [], (own, t))
                self.assertIsNone(act_a.peer, (own, t))
        self.assertIsNone(pa.current)
        self.assertEqual(b.sessions, before)             # no new session from any retyped message

    def test_responses_are_smaller_than_the_initiation(self):
        """No amplification (ch. 21 reflection attacks): a spoofed INIT gets a cookie reply and
        a valid INIT gets a RESP, and both are smaller than the INIT that caused them."""
        a, b, pa, init = unfinished()
        (resp, _), = b.handle(init, A_ADDR).send
        self.assertLess(len(resp), len(init))
        clk = FakeClock(1000.0)
        probe = Node(X25519PrivateKey.generate(), b"", clk, load_threshold=0)
        probe.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
        init_p = make_initiation(a._priv, a.pub, a._kem_priv, probe.pub, probe.kem_pub, b"", 5, _tai64n(time.time_ns()))[0]
        (cookie, _), = probe.handle(init_p, A_ADDR, 1000.0).send
        self.assertLess(len(cookie), len(init_p))

    def test_authenticated_data_gets_no_reply(self):
        """A reflected or replayed data packet never produces a reply from the receiver."""
        a, b = pair()
        pkt, _ = a.send(a.peers[b.pub], b"\x45" + bytes(19))
        act = b.handle(pkt, A_ADDR)
        self.assertEqual(act.send, [])
        self.assertEqual(b.handle(pkt, A_ADDR).send, [])

    def test_data_packet_is_not_accepted_by_the_sender_session(self):
        """Reflection (ch. 4): a packet sent by A cannot be fed back to A. Its direction key
        differs, so A's receive key rejects it."""
        a, b = pair()
        pa = a.peers[b.pub]
        pkt, _ = a.send(pa, b"\x45" + bytes(19))
        cur = pa.current
        # Same keys and indices, but a fresh replay window, so only the key direction can reject it.
        as_receiver = Session(local_index=cur.local_index, remote_index=cur.remote_index,
                                   send_key=cur.send_key, recv_key=cur.recv_key,
                                   created=cur.created, initiator=True)
        with self.assertRaises(ESPError) as cm:
            open_data(as_receiver, pkt)
        self.assertEqual(cm.exception.reason, "auth failed")

    def test_reflected_response_is_not_a_valid_initiator_proof(self):
        """A RESP built from a guessed chaining key is refused. The control RESP from the real
        responder is accepted."""
        a, b, pa, init = unfinished()
        (resp, _), = b.handle(init, A_ADDR).send
        consume_response(pa.pending, resp)                              # control: must not raise
        guess = InitInfo(peer_pub=a.pub, sender=pa.pending.sender, timestamp=b"",
                              eph_pub=init[8:40], ck=os.urandom(32), h=os.urandom(32))
        forged, _, _ = make_response(guess, 777, b"", a.kem_pub)
        with self.assertRaises(HandshakeError):
            consume_response(pa.pending, forged)

    def test_leaked_server_x25519_key_alone_cannot_read_an_initiation(self):
        """Impersonating the server needs its ML-KEM secret as well. With only its X25519 key, an
        attacker cannot open a client's INIT, because the chaining key depends on the KEM secret."""
        clk = FakeClock(1000.0)
        server = Node(X25519PrivateKey.generate(), b"", clk)
        client = Node(X25519PrivateKey.generate(), b"", clk)
        server.add_peer(client.pub, A_ADDR, kem_pub=client.kem_pub)
        client.add_peer(server.pub, B_ADDR, kem_pub=server.kem_pub)
        (init, _), = client.initiate(client.peers[server.pub], 1000.0)
        attacker_kem = mlkem.MLKEM768PrivateKey.generate()          # the attacker's own, not the server's
        with self.assertRaises(HandshakeError):
            consume_initiation(server._priv, server.pub, server.kem_pub, attacker_kem, init)

    def test_leaked_client_x25519_key_alone_gives_no_session(self):
        """Impersonating a client needs its ML-KEM secret too. An INIT that claims the client's identity,
        built with the leaked X25519 key, is accepted as a pending session. The server cannot make it
        current, because its response is encapsulated to the client's real ML-KEM key."""
        clk = FakeClock(1000.0)
        victim_priv = X25519PrivateKey.generate()
        victim = Node(victim_priv, b"", clk)
        server = Node(X25519PrivateKey.generate(), b"", clk)
        server.add_peer(victim.pub, A_ADDR, kem_pub=victim.kem_pub)
        attacker_kem = mlkem.MLKEM768PrivateKey.generate()
        forged, st = make_initiation(victim_priv, victim.pub, attacker_kem, server.pub, server.kem_pub,
                                          b"", 77, _tai64n(time.time_ns()))
        act = server.handle(forged, A_ADDR, 1000.0)
        (resp, _), = act.send
        self.assertIsNone(server.peers[victim.pub].current)
        self.assertIsNotNone(server.peers[victim.pub].next)
        with self.assertRaises(HandshakeError):                     # the attacker cannot finish
            consume_response(st, resp)

    def test_psk_stops_pose_as_client_with_leaked_server_key(self):
        """With a PSK set, an INIT built without the PSK gets no reply."""
        clk = FakeClock(1000.0)
        server = Node(X25519PrivateKey.generate(), PSK, clk)
        client = Node(X25519PrivateKey.generate(), b"", clk)
        server.add_peer(client.pub, A_ADDR, kem_pub=client.kem_pub)
        forged, _ = make_initiation(client._priv, client.pub, client._kem_priv, server.pub, server.kem_pub,
                                         b"", 77, _tai64n(time.time_ns()))
        act = server.handle(forged, A_ADDR, 1000.0)
        self.assertEqual(act.send, [])
        self.assertEqual(server.sessions, {})


class MutationFuzzTests(unittest.TestCase):
    """Mutation fuzzing, the verification step named in ch. 27. Valid handshake and data messages
    are changed at random and fed to the parser. Parsing must never raise. A change to any byte
    that is covered by mac1 or the AEAD must never be accepted. mac2 is not checked without load,
    so a change there is allowed to pass."""

    ROUNDS = 300

    @staticmethod
    def _mutate(rnd, msg: bytes):
        kind = rnd.randrange(4)
        if kind == 0:                                  # flip one bit
            i = rnd.randrange(len(msg))
            out = bytearray(msg)
            out[i] ^= 1 << rnd.randrange(8)
            return bytes(out), i
        if kind == 1:                                  # overwrite one byte
            i = rnd.randrange(len(msg))
            out = bytearray(msg)
            out[i] = rnd.randrange(256)
            return bytes(out), i
        if kind == 2:                                  # truncate
            return msg[:rnd.randrange(len(msg))], None
        return msg + os.urandom(rnd.randrange(1, 64)), None   # extend

    def test_mutated_handshake_messages_never_raise_or_establish_a_session(self):
        import random
        rnd = random.Random(20260)
        for _ in range(self.ROUNDS):
            a, b, pa, init = unfinished()
            (resp, _), = b.handle(init, A_ADDR).send
            mutated, idx = self._mutate(rnd, init)
            if mutated != init:
                act = b.handle(mutated, A_ADDR)        # must not raise
                if idx is None or idx < INIT_MAC1 + TAG_LEN:
                    self.assertEqual(act.send, [])
            mutated, idx = self._mutate(rnd, resp)
            if mutated != resp:
                a.handle(mutated, B_ADDR)              # must not raise
                if idx is None or idx < RESP_MAC1 + TAG_LEN:
                    self.assertIsNone(pa.current)

    def test_mutated_data_packets_are_never_delivered(self):
        import random
        rnd = random.Random(777)
        for _ in range(self.ROUNDS):
            a, b = pair()
            pa = a.peers[b.pub]
            pkt, _ = a.send(pa, b"\x45" + bytes(19))
            mutated, _ = self._mutate(rnd, pkt)
            if mutated == pkt:
                continue
            act = b.handle(mutated, A_ADDR)            # must not raise
            self.assertIsNone(act.peer)
            self.assertEqual(act.send, [])


class PostQuantumTests(unittest.TestCase):
    """Static ML-KEM-768 keys: the handshake step, its sizes, the key checks, and the profiles."""

    def test_messages_carry_the_ml_kem_fields(self):
        """INIT and RESP carry the ML-KEM ciphertext at the stated offsets, and the lengths match."""
        a, b, pa, init = unfinished()
        self.assertEqual(len(init), INIT_LEN)
        self.assertEqual(INIT_LEN, 1236)
        self.assertEqual(len(init[40:1128]), KEM_CT_LEN)
        (resp, _), = b.handle(init, A_ADDR).send
        self.assertEqual(len(resp), RESP_LEN)
        self.assertEqual(RESP_LEN, 1180)
        self.assertEqual(len(resp[44:1132]), KEM_CT_LEN)

    def test_tampered_ml_kem_ciphertext_is_rejected(self):
        """A changed byte in the RESP's ML-KEM ciphertext (mac1 recomputed) fails the key confirmation."""
        a, b, pa, init = unfinished()
        (resp, _), = b.handle(init, A_ADDR).send
        bad = bytearray(resp)
        bad[60] ^= 0x01                                    # inside the ciphertext
        act = a.handle(remac1(bytes(bad), RESP_MAC1, a.pub, b""), B_ADDR)
        self.assertIsNone(pa.current)
        self.assertTrue(any(HS_FAIL in e for e in act.events), act.events)

    def test_init_for_another_responder_kem_key_is_rejected(self):
        """Only the responder's ML-KEM secret opens an INIT. One encapsulated to another key is refused."""
        server = Node(X25519PrivateKey.generate())
        client = Node(X25519PrivateKey.generate())
        wrong = mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw()
        msg, _ = make_initiation(client._priv, client.pub, client._kem_priv, server.pub, wrong, b"", 9,
                                      _tai64n(time.time_ns()))
        with self.assertRaises(HandshakeError):
            consume_initiation(server._priv, server.pub, server.kem_pub, server._kem_priv, msg)

    def test_add_peer_refuses_a_malformed_ml_kem_key(self):
        """FIPS 203 key check: a key whose 12-bit coefficients exceed the modulus is refused."""
        node = Node(X25519PrivateKey.generate())
        peer = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        with self.assertRaises(ValueError):
            node.add_peer(peer, A_ADDR, kem_pub=bytes([0xFF]) * KEM_EK_LEN)

    def test_peer_without_an_ml_kem_key_cannot_handshake(self):
        """Fail closed: a peer with no ML-KEM key is never sent an INIT."""
        node = Node(X25519PrivateKey.generate(), clock=FakeClock(1000.0))
        peer_pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        peer = node.add_peer(peer_pub, A_ADDR)
        self.assertEqual(node.initiate(peer, 1000.0), [])

    def test_standard_profile_keeps_the_paper_timers(self):
        self.assertEqual(STANDARD.rekey_after_time, 120.0)
        self.assertEqual(STANDARD.reject_after_time, 180.0)

    def test_strict_profile_rotates_session_keys_sooner(self):
        """strict: a used session is due for rekey after 30 s and may not send after 45 s."""
        clk = FakeClock(1000.0)
        a = Node(X25519PrivateKey.generate(), b"", clk, profile=STRICT)
        b = Node(X25519PrivateKey.generate(), b"", clk)
        pa = a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
        b.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
        (init, _), = a.initiate(pa, 1000.0)
        (resp, _), = b.handle(init, A_ADDR, 1000.0).send
        a.handle(resp, B_ADDR, 1000.0)
        sess = pa.current
        self.assertEqual((sess.rekey_after, sess.reject_after), (30.0, 45.0))
        sess.send_counter = 1                               # a used session
        self.assertFalse(a._rekey_due(sess, 1029.0))
        self.assertTrue(a._rekey_due(sess, 1030.0))


if __name__ == "__main__":
    unittest.main()
