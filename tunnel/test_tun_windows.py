"""Open issue 13: the Windows TUN backend, tested against a fake wintun.dll.

The real DLL needs administrator rights to create an adapter, so these tests use a fake that follows the
same function signatures. Run the real check from an elevated shell with `python tun_windows.py --selftest`
(see the README).
"""
import ctypes
import queue
import select
import subprocess
import time
import unittest

import tun_windows
from tun_windows import WindowsTun, WinTunError, build_netsh_commands


class FakeWintun:
    """The Wintun calls WindowsTun makes, with the same return conventions (0/None means failure)."""

    def __init__(self):
        self.incoming = queue.Queue()     # packets the "adapter" delivers to the host
        self.sent = []                    # packets the host wrote into the ring
        self.adapter_created = False
        self.adapter_closed = False
        self.session_ended = False
        self.fail_create = False
        self.ring_full = False
        self._live = []                   # keep ctypes buffers alive while their addresses are in use
        self._alloc = None

    def WintunCreateAdapter(self, name, tunnel_type, guid):
        if self.fail_create:
            return None
        self.adapter_created = True
        return "adapter"

    def WintunCloseAdapter(self, adapter):
        self.adapter_closed = True

    def WintunStartSession(self, adapter, capacity):
        return "session"

    def WintunEndSession(self, session):
        self.session_ended = True

    def WintunGetReadWaitEvent(self, session):
        return 0

    def WintunReceivePacket(self, session, size_ref):
        if self.incoming.empty():
            return None
        data = self.incoming.get_nowait()
        buf = ctypes.create_string_buffer(data, len(data))
        self._live.append(buf)
        size_ref._obj.value = len(data)
        return ctypes.addressof(buf)

    def WintunReleaseReceivePacket(self, session, ptr):
        pass

    def WintunAllocateSendPacket(self, session, size):
        if self.ring_full:
            return None
        self._alloc = ctypes.create_string_buffer(size)
        return ctypes.addressof(self._alloc)

    def WintunSendPacket(self, session, ptr):
        self.sent.append(bytes(self._alloc.raw))


def no_wait(handle, timeout_ms):
    time.sleep(0.005)


class WindowsTunTests(unittest.TestCase):

    def make(self, lib=None, **kw):
        lib = lib or FakeWintun()
        tun = WindowsTun(lib=lib, wait=no_wait, **kw)
        self.addCleanup(tun.close)
        return lib, tun

    def test_packets_from_the_adapter_are_readable_in_order(self):
        lib, tun = self.make()
        packets = [bytes([0x45]) + bytes(i for i in range(39)), b"\x45" * 60, b"\x45" * 20]
        for p in packets:
            lib.incoming.put(p)
        got = []
        for _ in packets:
            readable, _, _ = select.select([tun.fileno()], [], [], 2.0)
            self.assertTrue(readable, "select() did not see a packet")
            got.append(tun.read_packet())
        self.assertEqual(got, packets)

    def test_write_packet_puts_the_datagram_into_the_ring(self):
        lib, tun = self.make()
        pkt = b"\x45" + b"\x01" * 39
        tun.write_packet(pkt)
        self.assertEqual(lib.sent, [pkt])

    def test_a_full_send_ring_is_an_error_not_a_silent_drop(self):
        lib, tun = self.make()
        lib.ring_full = True
        with self.assertRaises(WinTunError):
            tun.write_packet(b"\x45" + bytes(39))

    def test_oversized_packet_is_refused(self):
        lib, tun = self.make()
        with self.assertRaises(WinTunError):
            tun.write_packet(bytes(tun_windows.MAX_PACKET + 1))

    def test_close_ends_the_session_and_the_adapter(self):
        lib = FakeWintun()
        tun = WindowsTun(lib=lib, wait=no_wait)
        tun.close()
        tun.close()                                       # a second close is harmless
        self.assertTrue(lib.session_ended)
        self.assertTrue(lib.adapter_closed)

    def test_failing_to_create_the_adapter_says_so(self):
        lib = FakeWintun()
        lib.fail_create = True
        with self.assertRaises(WinTunError) as cm:
            WindowsTun(lib=lib, wait=no_wait)
        self.assertIn("administrator", str(cm.exception))

    def test_netsh_failure_closes_the_adapter_and_raises(self):
        lib = FakeWintun()

        def failing(cmd, **kw):
            raise subprocess.CalledProcessError(1, cmd, stderr="The requested operation requires elevation.")
        with self.assertRaises(WinTunError) as cm:
            WindowsTun(lib=lib, address="10.8.0.1/24", routes=["10.8.0.0/24"], run=failing, wait=no_wait)
        self.assertIn("elevation", str(cm.exception))
        self.assertTrue(lib.adapter_closed)


class NetshCommandTests(unittest.TestCase):

    def test_address_mtu_and_route_commands(self):
        cmds = build_netsh_commands("ioessa", "10.8.0.1/24", 1400, ["10.8.0.0/24"])
        self.assertIn("address=10.8.0.1", cmds[0])
        self.assertIn("mask=255.255.255.0", cmds[0])
        self.assertIn("mtu=1400", cmds[1])
        self.assertEqual(cmds[2][:6], ["netsh", "interface", "ipv4", "add", "route", "10.8.0.0/24"])

    def test_bad_prefix_is_refused_before_anything_runs(self):
        with self.assertRaises(ValueError):
            build_netsh_commands("ioessa", "10.8.0.1/24", 1400, ["10.8.0.1/24"])     # host bits set


if __name__ == "__main__":
    unittest.main()
