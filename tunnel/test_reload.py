"""Runtime peer revocation (peer_reload.PeerFileWatcher): a peer removed from the peer file loses its
sessions without a restart, a bad file is refused, and an unchanged file is not re-read."""
import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from peer_reload import PeerFileWatcher
from vpn_crypto import encode_key
from vpn_ip import build_ipv4, Policy, PROTECT
from vpn_node import handshake_local, Node
import ipaddress

A_ADDR = ("127.0.0.1", 40000)


def _entry(node: Node) -> str:
    return f"{encode_key(node.pub)}:{encode_key(node.kem_pub)}"


class PeerRevocationTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ioessa-reload-test-")
        self.path = os.path.join(self.dir, "peers.txt")
        self.messages = []

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, text: str) -> None:
        with open(self.path, "w", encoding="ascii") as f:
            f.write(text)
        os.chmod(self.path, 0o600)          # a peer file with a PSK must be owner-only (SELF_AUDIT S2)

    def _watcher(self, node, configure=lambda peer: None, check_disjoint=False):
        return PeerFileWatcher(node, self.path, configure, self.messages.append, keepalive=None,
                               interval=5.0, check_disjoint=check_disjoint)

    def test_revoked_peer_loses_its_sessions_without_a_restart(self):
        a, b = handshake_local()
        other = Node(X25519PrivateKey.generate())
        self._write(_entry(other))                       # the file no longer lists a
        watcher = self._watcher(b)
        watcher(0.0)
        self.assertNotIn(a.pub, b.peers)
        self.assertEqual(b.sessions, {})
        # a's traffic, still under the old session, is now refused by b
        a.peers[b.pub].spd = [Policy(ipaddress.IPv4Network("0.0.0.0/0"), PROTECT)]
        wire, _ = a.send(a.peers[b.pub], build_ipv4("10.8.0.2", "10.8.0.1", 253, b"after revoke"), 0.0)
        act = b.handle(wire, A_ADDR, 0.0)
        self.assertIsNone(act.inner)
        self.assertTrue(any("unknown index" in e for e in act.events), act.events)
        self.assertTrue(any("removed" in m for m in self.messages), self.messages)

    def test_new_peer_is_added_and_configured(self):
        a, b = handshake_local()
        new = Node(X25519PrivateKey.generate())
        self._write(_entry(a) + "," + _entry(new))
        seen = []
        watcher = self._watcher(b, configure=seen.append)
        watcher(0.0)
        self.assertIn(new.pub, b.peers)
        self.assertEqual(b.peers[new.pub].kem_pub, new.kem_pub)
        self.assertEqual([p.pub for p in seen], [new.pub])

    def test_bad_file_is_refused_and_current_peers_stay(self):
        a, b = handshake_local()
        self._write("not a key at all")
        self._watcher(b)(0.0)
        self.assertIn(a.pub, b.peers)
        self.assertTrue(any("refused" in m for m in self.messages), self.messages)

    def test_empty_file_is_refused_so_a_bad_edit_does_not_lock_everyone_out(self):
        a, b = handshake_local()
        self._write("")
        self._watcher(b)(0.0)
        self.assertIn(a.pub, b.peers)

    def test_unchanged_file_is_not_read_again(self):
        a, b = handshake_local()
        self._write(_entry(a))
        watcher = self._watcher(b)
        watcher(0.0)
        self.messages.clear()
        watcher(10.0)                                    # interval passed, file unchanged
        self.assertEqual(self.messages, [])

    def test_check_is_rate_limited_to_the_interval(self):
        a, b = handshake_local()
        self._write(_entry(a))
        watcher = self._watcher(b)
        watcher(0.0)
        other = Node(X25519PrivateKey.generate())
        self._write(_entry(other))
        watcher(1.0)                                     # inside the 5 s interval: not checked yet
        self.assertIn(a.pub, b.peers)
        watcher(6.0)
        self.assertNotIn(a.pub, b.peers)

    def test_tun_mode_refuses_a_second_overlapping_peer(self):
        """With --tun linux every peer shares the routes, so a second peer must not be added."""
        a, b = handshake_local()
        routes = [ipaddress.IPv4Network("10.8.0.0/24")]
        for peer in b.peers.values():
            peer.allowed_ips = routes
        extra = Node(X25519PrivateKey.generate())
        self._write(_entry(a) + "," + _entry(extra))

        def configure(peer):
            peer.allowed_ips = routes

        self._watcher(b, configure=configure, check_disjoint=True)(0.0)
        self.assertNotIn(extra.pub, b.peers)
        self.assertIn(a.pub, b.peers)
        self.assertTrue(any("not added" in m for m in self.messages), self.messages)


if __name__ == "__main__":
    unittest.main()
