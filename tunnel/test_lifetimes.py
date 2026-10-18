"""Session lifetimes and secret rotation, after the open-issues pass.

- Item 6: a session has a byte limit (REKEY_AFTER_BYTES), like the message-count limit.
- Item 17: the cookie secret rotates from the timers, not only when an INIT arrives.
- Item 19: a session older than three reject periods refuses received data between timer ticks.
"""
import unittest

from vpn_ip import build_ipv4

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from test_vpn import A_ADDR, B_ADDR, FakeClock, pair
from vpn_constants import COOKIE_SECRET_TIME, REJECT_AFTER_TIME, REKEY_AFTER_BYTES
from vpn_errors import RekeyRequired
from vpn_node import Node


class ByteLifetimeTests(unittest.TestCase):

    def test_send_bytes_are_counted_and_limit_forces_rekey(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pa = a.peers[b.pub]
        pa.current.byte_limit = 160                      # two 80-byte datagrams fit, the third does not
        inner = b"\x45" + b"\x00" * 79
        a.send(pa, inner, clk.t)
        a.send(pa, inner, clk.t)
        self.assertEqual(pa.current.send_bytes, 160)
        with self.assertRaises(RekeyRequired):
            a.send(pa, inner, clk.t)
        self.assertTrue(a._rekey_due(pa.current, clk.t))

    def test_default_byte_limit_is_one_gib(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        self.assertEqual(a.peers[b.pub].current.byte_limit, REKEY_AFTER_BYTES)
        self.assertEqual(REKEY_AFTER_BYTES, 1 << 30)


class ReceiveAgeTests(unittest.TestCase):

    def test_fresh_session_accepts_data(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        inner = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x" * 20)
        pkt, _ = a.send(a.peers[b.pub], inner, clk.t)
        act = b.handle(pkt, A_ADDR, clk.t + 10)
        self.assertEqual(act.inner, inner)

    def test_session_past_three_reject_periods_refuses_data_before_the_tick(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        inner = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x" * 20)
        pkt, _ = a.send(a.peers[b.pub], inner, clk.t)
        act = b.handle(pkt, A_ADDR, clk.t + 3 * REJECT_AFTER_TIME + 1)
        self.assertIsNone(act.inner)
        self.assertTrue(any("session too old" in e for e in act.events), act.events)


class CookieRotationTests(unittest.TestCase):

    def test_poll_rotates_the_cookie_secret_without_an_init(self):
        node = Node(X25519PrivateKey.generate())
        start = node._secret_at
        node.poll(start + COOKIE_SECRET_TIME + 1)
        self.assertEqual(node._secret_at, start + COOKIE_SECRET_TIME + 1)

    def test_poll_before_the_period_keeps_the_secret(self):
        node = Node(X25519PrivateKey.generate())
        secret = node._secret
        node.poll(node._secret_at + COOKIE_SECRET_TIME / 2)
        self.assertEqual(node._secret, secret)


if __name__ == "__main__":
    unittest.main()
