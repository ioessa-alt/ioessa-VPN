"""Regression tests for model_check_init.py: the model's verdicts are part of the test suite, so a
change to the timestamp rule in the model, or to the reasoning behind it, shows up here."""
import unittest

import model_check_init as m


class InitTimestampModelTests(unittest.TestCase):

    def test_replay_safety_holds_for_the_current_rule(self):
        violations, _ = m.check(None)
        self.assertNotIn("replay_safety", violations)

    def test_current_rule_accepts_a_suppressed_init_late(self):
        """OPEN_ISSUES 16: a captured INIT that is held back and replayed later is accepted."""
        violations, _ = m.check(None)
        self.assertIn("freshness", violations)
        trace = violations["freshness"]
        self.assertIn("send 1", trace)
        self.assertEqual(trace[-1], "deliver 1 at 4")          # 3 s old, window is 2 s

    def test_freshness_window_removes_the_counterexample(self):
        violations, _ = m.check(m.WINDOW)
        self.assertEqual(violations, {})

    def test_freshness_window_keeps_replay_safety(self):
        violations, _ = m.check(m.WINDOW)
        self.assertNotIn("replay_safety", violations)

    def test_search_is_exhaustive_for_the_bounds(self):
        _, n = m.check(None)
        self.assertEqual(n, 2133)                               # reachable states for T_MAX=8, SENDS=2


if __name__ == "__main__":
    unittest.main()
