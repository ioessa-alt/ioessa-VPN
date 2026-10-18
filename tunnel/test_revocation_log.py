"""Open issue 13: a refused INIT from a removed key is logged as "revoked", not as "unknown".

The log line is local only. Nothing is sent back, so the wire is unchanged (ch. 15, P-I3).
"""
import unittest

from test_vpn import A_ADDR, FakeClock, unfinished
from vpn_node import Node
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class RevokedKeyLogTests(unittest.TestCase):

    def test_init_from_a_removed_key_is_logged_as_revoked(self):
        clk = FakeClock(1000.0)
        a, b, pa, init = unfinished(clock=clk)
        b.remove_peer(a.pub)
        act = b.handle(init, A_ADDR, clk.t)
        self.assertEqual(act.send, [])                              # still silent on the wire
        self.assertTrue(any("revoked peer key" in e for e in act.events), act.events)

    def test_init_from_a_never_configured_key_is_logged_as_unknown(self):
        clk = FakeClock(1000.0)
        a, b, pa, init = unfinished(clock=clk)
        b.peers.clear()                                             # b never heard of a, and no removal
        b.revoked.clear()
        act = b.handle(init, A_ADDR, clk.t)
        self.assertTrue(any("unknown peer key" in e for e in act.events), act.events)
        self.assertFalse(any("revoked" in e for e in act.events))

    def test_re_adding_a_revoked_key_clears_the_revocation(self):
        clk = FakeClock(1000.0)
        a, b, pa, init = unfinished(clock=clk)
        b.remove_peer(a.pub)
        self.assertIn(a.pub, b.revoked)
        b.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
        self.assertNotIn(a.pub, b.revoked)

    def test_removing_an_unknown_key_does_not_record_it(self):
        n = Node(X25519PrivateKey.generate())
        n.remove_peer(bytes(32))
        self.assertEqual(n.revoked, set())


if __name__ == "__main__":
    unittest.main()
