"""Open issue 1: a global INIT budget that tunes itself.

The budget counts INITs that pass mac1 (junk costs nothing). It starts at GLOBAL_HS_START per second,
rises 25% in any window that refused something, and falls to twice the admitted rate after three quiet
windows. It never leaves [GLOBAL_HS_FLOOR, GLOBAL_HS_CEIL].
"""
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from test_vpn import A_ADDR, FakeClock, unfinished
from vpn_constants import GLOBAL_HS_CEIL, GLOBAL_HS_FLOOR, GLOBAL_HS_START, GLOBAL_HS_TUNE_PERIOD, INIT_MAC1
from vpn_node import Node


class GlobalBudgetTests(unittest.TestCase):

    def node(self, clk):
        return Node(X25519PrivateKey.generate(), clock=clk)

    def test_starts_at_the_configured_rate(self):
        self.assertEqual(self.node(FakeClock(0.0)).global_hs_rate, GLOBAL_HS_START)

    def test_admits_up_to_the_rate_then_refuses_within_the_same_instant(self):
        clk = FakeClock(100.0)
        n = self.node(clk)
        n.global_hs_rate = 3.0
        n._gb_tokens = 3.0
        results = [n._global_hs_budget(100.0) for _ in range(5)]
        self.assertEqual(results, [True, True, True, False, False])

    def test_tokens_refill_at_the_rate(self):
        n = self.node(FakeClock(0.0))
        n.global_hs_rate = 10.0
        n._gb_tokens = 0.0
        n._global_hs_budget(0.0)                       # starts the clock
        self.assertFalse(n._global_hs_budget(0.05))    # half a token: refused
        self.assertTrue(n._global_hs_budget(0.2))      # 2 more tokens by now: admitted

    def test_refusals_raise_the_rate_by_a_quarter_at_the_end_of_the_window(self):
        n = self.node(FakeClock(0.0))
        n.global_hs_rate = 4.0
        n._gb_tokens = 0.0
        n._global_hs_budget(0.0)
        for _ in range(3):
            n._global_hs_budget(0.0)                   # refused in this window
        n._global_hs_budget(GLOBAL_HS_TUNE_PERIOD + 0.1)
        self.assertAlmostEqual(n.global_hs_rate, 5.0)

    def test_quiet_windows_lower_the_rate_to_twice_the_admitted_rate(self):
        n = self.node(FakeClock(0.0))
        n.global_hs_rate = 1000.0
        t = 0.0
        n._global_hs_budget(t)
        for window in range(3):
            n._gb_admitted = 1000                      # 1000 admitted in this window, none refused
            t += GLOBAL_HS_TUNE_PERIOD + 0.1
            n._global_hs_budget(t)
        self.assertAlmostEqual(n.global_hs_rate, 2 * 1000 / GLOBAL_HS_TUNE_PERIOD, places=1)     # 200/s

    def test_the_rate_never_leaves_its_bounds(self):
        n = self.node(FakeClock(0.0))
        n.global_hs_rate = GLOBAL_HS_CEIL
        n._gb_refused = 1
        n._gb_window_at = 0.0
        n._tune_global_hs(GLOBAL_HS_TUNE_PERIOD + 1)
        self.assertEqual(n.global_hs_rate, GLOBAL_HS_CEIL)
        n.global_hs_rate = GLOBAL_HS_FLOOR
        n._gb_quiet = 5
        n._gb_window_at = 0.0
        n._tune_global_hs(GLOBAL_HS_TUNE_PERIOD + 1)
        self.assertEqual(n.global_hs_rate, GLOBAL_HS_FLOOR)

    def test_junk_datagrams_do_not_use_the_budget(self):
        clk = FakeClock(1000.0)
        a, b, pa, init = unfinished(clock=clk)
        junk = bytearray(init)
        junk[INIT_MAC1] ^= 1                    # breaks mac1, so the INIT is dropped before the budget
        before = b._gb_admitted + b._gb_refused
        b.handle(bytes(junk), A_ADDR, clk.t)
        self.assertEqual(b._gb_admitted + b._gb_refused, before)


if __name__ == "__main__":
    unittest.main()
