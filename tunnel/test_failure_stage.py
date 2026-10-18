"""Open issue 18: a failed handshake names its step in the local log. The wire stays silent or generic.

The INIT is tampered inside the encrypted static key, then mac1 is recomputed (an attacker who knows
the public key can do that), so the datagram gets past the MAC check and fails at the AEAD step.
"""
import unittest

from test_vpn import A_ADDR, FakeClock, remac1, unfinished
from vpn_constants import INIT_MAC1


class FailureStageTests(unittest.TestCase):

    def test_tampered_static_key_is_logged_with_its_stage_and_sends_nothing(self):
        clk = FakeClock(1000.0)
        a, b, pa, init = unfinished(clock=clk)
        enc_static_start = INIT_MAC1 - 48 - 28            # enc_static (48) and enc_ts (28) precede mac1
        bad = bytearray(init)
        bad[enc_static_start + 5] ^= 1
        bad = remac1(bytes(bad), INIT_MAC1, b.pub, b"")
        act = b.handle(bad, A_ADDR, clk.t)
        self.assertEqual(act.send, [])                   # nothing on the wire
        joined = " ".join(act.events)
        self.assertIn("handshake failed", joined)
        self.assertIn("static key of the initiator", joined)


if __name__ == "__main__":
    unittest.main()
