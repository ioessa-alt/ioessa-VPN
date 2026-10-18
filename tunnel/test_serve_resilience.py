"""The server loop keeps serving after an unexpected exception, and Ctrl+C ends it cleanly.

Before this change, any exception other than HandshakeError or ESPError ended serve(). Now one
bad datagram or one failing timer run costs only that step. The log records the exception type,
never its message, so keys or packet bytes that an exception might carry are not printed.
"""
import io
import sys
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import vpn_server
from test_vpn import A_ADDR, FakeSock
from vpn_node import Action


class BuggyHandleNode:
    """Raises on the first datagram with a message that must not reach the log."""

    def __init__(self):
        self.calls = 0

    def clock(self):
        return 1000.0

    def handle(self, data, addr, now):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("secret-material-123")
        return Action()

    def poll(self, now):
        return []


class BuggyTimerNode:
    def clock(self):
        return 1000.0

    def handle(self, data, addr, now):
        return Action()

    def poll(self, now):
        raise ValueError("timer-secret-456")


class ServeContinuesTests(unittest.TestCase):

    def test_datagrams_after_a_bug_are_still_handled(self):
        node = BuggyHandleNode()
        sock = FakeSock(inbox=[(b"x" * 8, A_ADDR), (b"y" * 8, A_ADDR)])
        lines = []
        vpn_server.serve(sock, node, idle_timeout=None, out=lines.append)   # returns on the empty inbox
        self.assertEqual(node.calls, 2)                                     # the second one was handled
        self.assertTrue(any(l.startswith("internal error on datagram from") for l in lines), lines)

    def test_log_shows_the_exception_type_not_its_message(self):
        node = BuggyHandleNode()
        sock = FakeSock(inbox=[(b"x" * 8, A_ADDR)])
        lines = []
        vpn_server.serve(sock, node, idle_timeout=None, out=lines.append)
        self.assertIn("RuntimeError", " ".join(lines))
        self.assertNotIn("secret-material", " ".join(lines))

    def test_failing_timer_run_does_not_end_the_loop(self):
        sock = FakeSock(inbox=[])                                           # only the timeout path runs
        lines = []
        vpn_server.serve(sock, BuggyTimerNode(), idle_timeout=None, out=lines.append)
        joined = " ".join(lines)
        self.assertIn("internal error in timers: ValueError", joined)
        self.assertNotIn("timer-secret", joined)


class CtrlCTests(unittest.TestCase):

    def test_ctrl_c_prints_a_clean_stop_and_returns(self):
        argv = ["vpn_server.py", "--port", "0", "--bind", "127.0.0.1"]
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(vpn_server, "load_static_private", return_value=X25519PrivateKey.generate()), \
                mock.patch.object(vpn_server, "load_kem_private",
                                  return_value=mlkem.MLKEM768PrivateKey.generate()), \
                mock.patch.object(vpn_server, "load_peer_entries", return_value=[]), \
                mock.patch.object(vpn_server, "serve", side_effect=KeyboardInterrupt), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            vpn_server.main()                                               # must not raise
        self.assertIn("stopped (Ctrl+C)", out.getvalue())
        self.assertNotIn("Traceback", out.getvalue())


if __name__ == "__main__":
    unittest.main()
