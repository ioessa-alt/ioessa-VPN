"""Self-audit tests (SELF_AUDIT.md): exhaustive single-bit flips of INIT and RESP.

Every bit before mac1 is flipped in turn, mac1 is recomputed (an attacker knows the public key), and the
message is fed to the pure handshake functions. Only the unauthenticated index fields may survive a flip."""
import os
import tempfile
import unittest
from unittest import mock

from vpn_constants import INIT_MAC1, RESP_MAC1
from vpn_errors import HandshakeError
from vpn_handshake import consume_initiation, consume_response, finish_initiation
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from peer_reload import PeerFileWatcher
import vpn_keyfiles
from vpn_keyfiles import _parse_icacls, load_peer_entries
from vpn_crypto import encode_key
from vpn_node import Node
from test_vpn import A_ADDR, B_ADDR, remac1, unfinished

INDEX = range(4, 8)          # sender index: chosen by the sender, not part of the transcript


def _flips(msg: bytes, end: int):
    for pos in range(end):
        for bit in range(8):
            bad = bytearray(msg)
            bad[pos] ^= 1 << bit
            yield pos, bytes(bad)


class ExhaustiveFlipTests(unittest.TestCase):
    def _check(self, psk: bytes):
        a, b, pa, init = unfinished(psk)
        accepted, odd = set(), []
        for pos, bad in _flips(init, INIT_MAC1):
            try:
                info = consume_initiation(b._priv, b.pub, b.kem_pub, b._kem_priv, remac1(bad, INIT_MAC1, b.pub, psk))
                finish_initiation(info, b._priv, psk)
                accepted.add(pos)
            except HandshakeError:
                pass
            except Exception as exc:          # any other exception is a robustness finding
                odd.append((pos, type(exc).__name__))
        self.assertEqual(odd, [])
        self.assertEqual(accepted, set(INDEX), "INIT bytes outside the sender index survived a flip")

        (resp, _), = b.handle(init, A_ADDR).send
        st = pa.pending
        accepted, odd = set(), []
        for pos, bad in _flips(resp, RESP_MAC1):
            try:
                consume_response(st, remac1(bad, RESP_MAC1, a.pub, psk))
                accepted.add(pos)
            except HandshakeError:
                pass
            except Exception as exc:
                odd.append((pos, type(exc).__name__))
        self.assertEqual(odd, [])
        self.assertEqual(accepted, set(INDEX), "RESP bytes outside the sender index survived a flip")
        consume_response(st, resp)            # the untouched RESP still completes: the state was not consumed

    def test_every_bit_of_init_and_resp_is_bound_without_psk(self):
        self._check(b"")

    def test_every_bit_of_init_and_resp_is_bound_with_psk(self):
        self._check(bytes(range(32)))


class FixedFindingTests(unittest.TestCase):
    def test_s1_specific_rights_group_counts_as_a_grant(self):
        """icacls prints specific rights comma-joined; Everyone:(RD,REA,RA) can read the key and must be seen."""
        entries = _parse_icacls("k.key Everyone:(RD,REA,RA)\n      NT AUTHORITY\\SYSTEM:(I)(F)\n", "k.key")
        self.assertEqual(dict(entries)["Everyone"], frozenset({"RD", "REA", "RA"}))
        self.assertEqual(dict(entries)["SYSTEM"], frozenset({"F"}))

    def test_s1_integrity_label_is_not_a_grant(self):
        entries = _parse_icacls("k.key Mandatory Label\\High Mandatory Level:(NW)\n", "k.key")
        self.assertEqual(dict(entries)["High Mandatory Level"], frozenset())

    def test_s2_peer_file_with_a_psk_gets_the_permission_check(self):
        node = Node(X25519PrivateKey.generate())
        entry = encode_key(node.pub) + ":" + encode_key(node.kem_pub)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "peers.txt")
            for text, checked in ((entry, False), (entry + ":" + "ab" * 32, True)):
                with open(path, "w", encoding="ascii") as f:
                    f.write(text + "\n")
                with mock.patch.object(vpn_keyfiles, "_check_key_file_mode") as check:
                    load_peer_entries(path)
                self.assertEqual(check.called, checked, text)

    def test_s3_non_ascii_peer_file_keeps_peers_and_does_not_raise(self):
        node = Node(X25519PrivateKey.generate())
        node.add_peer(X25519PrivateKey.generate().public_key().public_bytes_raw(), A_ADDR,
                      kem_pub=node.kem_pub)
        lines = []
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "peers.txt")
            with open(path, "wb") as f:
                f.write("café\n".encode())
            PeerFileWatcher(node, path, lambda p: None, lines.append, None, interval=0)(0.0)
        self.assertEqual(len(node.peers), 1)
        self.assertTrue(any("refused" in l for l in lines), lines)


class ClaimTests(unittest.TestCase):
    def test_claim2_responder_holds_the_session_until_the_initiator_confirms(self):
        """The responder's new session waits in `next` and is promoted only by the initiator's first data."""
        a, b, pa, init = unfinished()
        (resp, _), = b.handle(init, A_ADDR).send
        pb = b.peers[a.pub]
        self.assertIsNone(pb.current)
        self.assertIsNotNone(pb.next)
        (keepalive, _), = a.handle(resp, B_ADDR).send
        b.handle(keepalive, A_ADDR)
        self.assertIsNotNone(pb.current)
        self.assertIsNone(pb.next)


if __name__ == "__main__":
    unittest.main()
