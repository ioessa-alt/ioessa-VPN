"""Open issues 2 and 4: a pre-shared key per peer, and a wire version byte.

The PSK is mixed in after the initiator's static key is identified, so the responder can pick the
right PSK for each peer. A wrong PSK fails at the timestamp AEAD, silently, like any other failure.
"""
import os
import tempfile
import unittest

from vpn_ip import build_ipv4

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from test_vpn import A_ADDR, B_ADDR, PROTECT_ALL, FakeClock
from vpn_crypto import encode_key, generate_kem_keypair
from vpn_keyfiles import load_peer_entries, load_peer_publics
from vpn_node import Node

INNER = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x" * 20)


def node_pair_with_psk(clk, psk_ab, psk_ba):
    """a and b, each knowing the other, with the PSK each side uses for the other."""
    a = Node(X25519PrivateKey.generate(), clock=clk)
    b = Node(X25519PrivateKey.generate(), clock=clk)
    pa = a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub, psk=psk_ab)
    b.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub, psk=psk_ba)
    pa.spd = list(PROTECT_ALL)                          # send through the tunnel, as test_vpn.pair() does
    b.peers[a.pub].spd = list(PROTECT_ALL)
    return a, b, pa


class PerPeerPskTests(unittest.TestCase):

    def test_matching_psk_completes_the_handshake_and_carries_data(self):
        clk = FakeClock(1000.0)
        key = os.urandom(32)
        a, b, pa = node_pair_with_psk(clk, key, key)
        (init, _), = a.initiate(pa, clk.t)
        (resp, _), = b.handle(init, A_ADDR, clk.t).send
        a.handle(resp, B_ADDR, clk.t)
        self.assertIsNotNone(pa.current)
        pkt, _ = a.send(pa, INNER, clk.t)
        self.assertEqual(b.handle(pkt, A_ADDR, clk.t).inner, INNER)

    def test_wrong_psk_is_refused_silently_with_the_stage_in_the_log(self):
        clk = FakeClock(1000.0)
        a, b, pa = node_pair_with_psk(clk, os.urandom(32), os.urandom(32))
        (init, _), = a.initiate(pa, clk.t)
        act = b.handle(init, A_ADDR, clk.t)
        self.assertEqual(act.send, [])
        self.assertTrue(any("wrong PSK" in e for e in act.events), act.events)

    def test_one_server_keeps_a_different_psk_per_peer(self):
        clk = FakeClock(1000.0)
        k1, k2 = os.urandom(32), os.urandom(32)
        server = Node(X25519PrivateKey.generate(), clock=clk)
        a1 = Node(X25519PrivateKey.generate(), clock=clk)
        a2 = Node(X25519PrivateKey.generate(), clock=clk)
        server.add_peer(a1.pub, A_ADDR, kem_pub=a1.kem_pub, psk=k1)
        server.add_peer(a2.pub, A_ADDR, kem_pub=a2.kem_pub, psk=k2)
        a1.add_peer(server.pub, B_ADDR, kem_pub=server.kem_pub, psk=k1)
        a2_wrong = Node(a2._priv, clock=clk)
        a2_wrong.add_peer(server.pub, B_ADDR, kem_pub=server.kem_pub, psk=k1)   # a2 with a1's key: refused
        p1 = a1.peers[server.pub]
        (init1, _), = a1.initiate(p1, clk.t)
        self.assertTrue(server.handle(init1, A_ADDR, clk.t).send)               # matching PSK: answered
        (init2, _), = a2_wrong.initiate(a2_wrong.peers[server.pub], clk.t)
        self.assertEqual(server.handle(init2, A_ADDR, clk.t).send, [])          # wrong PSK: silent

    def test_default_psk_applies_to_peers_added_without_one(self):
        clk = FakeClock(1000.0)
        key = os.urandom(32)
        n = Node(X25519PrivateKey.generate(), key, clock=clk)
        peer = n.add_peer(X25519PrivateKey.generate().public_key().public_bytes_raw(), B_ADDR,
                          kem_pub=Node(X25519PrivateKey.generate()).kem_pub)
        self.assertEqual(peer.psk, key)

    def test_short_or_zero_psk_is_refused(self):
        clk = FakeClock(1000.0)
        n = Node(X25519PrivateKey.generate(), clock=clk)
        peer_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()
        kem = Node(X25519PrivateKey.generate()).kem_pub
        with self.assertRaises(ValueError):
            n.add_peer(peer_pub, B_ADDR, kem_pub=kem, psk=b"short")
        with self.assertRaises(ValueError):
            n.add_peer(peer_pub, B_ADDR, kem_pub=kem, psk=bytes(32))


class PeerFileFormatTests(unittest.TestCase):

    def write(self, text):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(text)
        self.addCleanup(os.remove, path)
        return path

    def entry(self, psk_hex=None):
        pub = encode_key(X25519PrivateKey.generate().public_key().public_bytes_raw())
        _, kem_pub = generate_kem_keypair()
        base = f"{pub}:{encode_key(kem_pub)}"
        return base if psk_hex is None else f"{base}:{psk_hex}"

    def test_entry_with_psk_field_returns_the_psk(self):
        key = os.urandom(32)
        path = self.write(self.entry(key.hex()) + "\n")
        ((pub, kem, psk),) = load_peer_entries(path)
        self.assertEqual(psk, key)

    def test_entry_without_psk_field_returns_empty_psk(self):
        path = self.write(self.entry() + "\n")
        ((pub, kem, psk),) = load_peer_entries(path)
        self.assertEqual(psk, b"")

    def test_bad_psk_fields_are_refused(self):
        for bad in ("zz", "00" * 8, "00" * 32, ""):
            with self.subTest(bad=bad):
                path = self.write(self.entry(bad) + "\n")
                with self.assertRaises(RuntimeError):
                    load_peer_entries(path)

    def test_load_peer_publics_still_returns_pairs(self):
        path = self.write(self.entry(os.urandom(32).hex()) + "\n")
        ((pub, kem),) = load_peer_publics(path)
        self.assertEqual(len(pub), 32)


class AllowedIpsDefaultTests(unittest.TestCase):
    """Open issue 14: without an explicit allowed_ips, a peer may only send from the tunnel subnet."""

    def test_default_allows_the_tunnel_subnet_and_refuses_others(self):
        from vpn_ip import build_ipv4
        clk = FakeClock(1000.0)
        a, b, pa = node_pair_with_psk(clk, b"", b"")
        (init, _), = a.initiate(pa, clk.t)
        (resp, _), = b.handle(init, A_ADDR, clk.t).send
        a.handle(resp, B_ADDR, clk.t)
        inside = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"ok" * 10)
        outside = build_ipv4("8.8.8.8", "10.8.0.1", 253, b"no" * 10)
        pkt_in, _ = a.send(pa, inside, clk.t)
        pkt_out, _ = a.send(pa, outside, clk.t)
        self.assertEqual(b.handle(pkt_in, A_ADDR, clk.t).inner, inside)
        act = b.handle(pkt_out, A_ADDR, clk.t)
        self.assertIsNone(act.inner)
        self.assertTrue(any("source not allowed" in e for e in act.events), act.events)


class WireVersionTests(unittest.TestCase):

    def test_datagram_with_another_wire_version_is_dropped_before_parsing(self):
        clk = FakeClock(1000.0)
        a, b, pa = node_pair_with_psk(clk, b"", b"")
        (init, _), = a.initiate(pa, clk.t)
        other = bytearray(init)
        other[1] = 1                                    # version 1, the protocol before this change
        act = b.handle(bytes(other), A_ADDR, clk.t)
        self.assertEqual(act.send, [])
        self.assertEqual(act.events, [])                # nothing is parsed, so nothing is logged

    def test_data_packets_carry_the_version(self):
        from vpn_constants import WIRE_VERSION
        clk = FakeClock(1000.0)
        a, b, pa = node_pair_with_psk(clk, b"", b"")
        (init, _), = a.initiate(pa, clk.t)
        (resp, _), = b.handle(init, A_ADDR, clk.t).send
        a.handle(resp, B_ADDR, clk.t)
        pkt, _ = a.send(pa, INNER, clk.t)
        self.assertEqual(pkt[1], WIRE_VERSION)


if __name__ == "__main__":
    unittest.main()
