"""Regression tests for two fixes: the all-zero PSK check and ConnectionResetError handling."""
import os
import secrets
import unittest
from unittest import mock

import vpn_client
from vpn_constants import PSK_ENV
from vpn_keyfiles import load_psk


class FakeSock:
    """Replays a list of recvfrom results; an Exception item is raised instead of returned."""

    def __init__(self, items):
        self.items = list(items)

    def settimeout(self, _):
        pass

    def recvfrom(self, _n):
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class PskCheckTests(unittest.TestCase):
    def test_all_zero_psk_is_rejected(self):
        with mock.patch.dict(os.environ, {PSK_ENV: "00" * 32}):
            with self.assertRaises(RuntimeError) as cm:
                load_psk()
        self.assertIn("all zeros", str(cm.exception))

    def test_random_psk_is_accepted(self):
        key = secrets.token_hex(32)
        with mock.patch.dict(os.environ, {PSK_ENV: key}):
            self.assertEqual(load_psk(), bytes.fromhex(key))

    def test_short_psk_is_still_rejected(self):
        with mock.patch.dict(os.environ, {PSK_ENV: "ab" * 16}):
            with self.assertRaises(RuntimeError):
                load_psk()


class ConnectionResetTests(unittest.TestCase):
    SERVER = ("127.0.0.1", 4500)

    def test_recv_survives_icmp_reset_and_returns_server_datagram(self):
        good = b"x" * 40
        sock = FakeSock([ConnectionResetError(10054, "reset"), (good, self.SERVER)])
        self.assertEqual(vpn_client._recv_from(sock, self.SERVER, timeout=5), good)

    def test_recv_times_out_when_only_resets_arrive(self):
        # Only resets, forever: the deadline must still end the wait.
        class AlwaysReset(FakeSock):
            def recvfrom(self, _n):
                raise ConnectionResetError(10054, "reset")

        with mock.patch.object(vpn_client.time, "monotonic", side_effect=[0, 0, 0.5, 2.0]):
            with self.assertRaises(vpn_client.socket.timeout):
                vpn_client._recv_from(AlwaysReset([]), self.SERVER, timeout=1.0)


if __name__ == "__main__":
    unittest.main()
