"""Open issue 6: INIT timestamps must be within FRESHNESS_WINDOW (180 s) of the responder's wall clock.

A correctly signed and encrypted INIT with an old timestamp is refused. The window stops a held-back
INIT from being accepted later, even when the responder has no newer INIT on record.
"""
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from test_vpn import A_ADDR, B_ADDR, FakeClock
from vpn_constants import FRESHNESS_WINDOW
from vpn_crypto import _tai64n, _tai64n_to_unix
from vpn_handshake import make_initiation
from vpn_node import Node


def signed_init(a, b, unix_time):
    msg, _ = make_initiation(a._priv, a.pub, a._kem_priv, b.pub, b.kem_pub, b"", 77,
                             _tai64n(int(unix_time * 1e9)))
    return msg


class FreshnessTests(unittest.TestCase):

    def setUp(self):
        self.clk = FakeClock(1000.0)
        self.a = Node(X25519PrivateKey.generate(), clock=self.clk)
        self.b = Node(X25519PrivateKey.generate(), clock=self.clk)
        self.a.add_peer(self.b.pub, B_ADDR, kem_pub=self.b.kem_pub)
        self.b.add_peer(self.a.pub, A_ADDR, kem_pub=self.a.kem_pub)

    def test_timestamp_round_trips(self):
        now = time.time()
        self.assertAlmostEqual(_tai64n_to_unix(_tai64n(int(now * 1e9))), now, delta=1e-6)

    def test_old_but_valid_init_is_refused_by_the_window(self):
        old = signed_init(self.a, self.b, time.time() - FRESHNESS_WINDOW - 60)
        act = self.b.handle(old, A_ADDR, self.clk.t)
        self.assertEqual(act.send, [])
        self.assertTrue(any("freshness window" in e for e in act.events), act.events)

    def test_fresh_init_is_accepted(self):
        fresh = signed_init(self.a, self.b, time.time())
        act = self.b.handle(fresh, A_ADDR, self.clk.t)
        self.assertTrue(act.send, act.events)

    def test_a_timestamp_from_the_future_beyond_the_window_is_refused(self):
        future = signed_init(self.a, self.b, time.time() + FRESHNESS_WINDOW + 60)
        act = self.b.handle(future, A_ADDR, self.clk.t)
        self.assertEqual(act.send, [])


if __name__ == "__main__":
    unittest.main()
