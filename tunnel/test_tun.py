"""Tests for the TUN backend, and for the TUN loops in vpn_server and vpn_client.

Run from this folder with: python -m unittest test_tun

None of these tests needs root or a TUN device. They cover:
  * argument validation and the `ip` argument lists (no commands are run for real);
  * the MTU math, checked against packets that vpn_transport really seals;
  * the ioctl constant and the struct layout, against the _IOW encoding and the ifreq layout;
  * the platform error (LinuxTun must refuse to start off Linux);
  * the select() loops in serve_tun and run_tun, over real loopback UDP sockets, with a
    socketpair standing in for the device.

They do not prove that a real TUN device works. That needs Linux and root (see README.md).
"""
import contextlib
import ipaddress
import socket
import struct
import subprocess
import sys
import types
import threading
import unittest
from unittest import mock

import tun_linux
import vpn_client
import vpn_server
from tun_linux import (CLONE_DEVICE, DEFAULT_MTU, IFF_NO_PI, IFF_TUN, IFNAMSIZ, IFREQ, IPV4_HDR, LinuxTun,
                       TUNSETIFF, TunError, UDP_HDR, _run_ip, build_ip_commands, is_ipv4, max_tun_mtu,
                       tunnel_overhead, validate_address, validate_mtu, validate_name, validate_route)
from vpn_constants import DATA_HDR_LEN, MAX_INNER, TAG_LEN
from vpn_crypto import new_private_key
from vpn_ip import build_ipv4, Policy, PROTECT
from vpn_node import handshake_local, Node
from vpn_tun import TunDevice

ANY = ipaddress.IPv4Network("0.0.0.0/0")


def _IOW(type_char: str, nr: int, size: int) -> int:
    """Linux _IOW(type, nr, size) from include/uapi/asm-generic/ioctl.h, for a write ioctl."""
    _IOC_WRITE = 1
    return (_IOC_WRITE << 30) | (size << 16) | (ord(type_char) << 8) | nr


class ValidationTests(unittest.TestCase):
    def test_name_accepts_kernel_style_names(self):
        for name in ("ioessa0", "tun0", "vpn_1", "a-b", "x" * 15):
            self.assertEqual(validate_name(name), name)

    def test_name_rejects_shell_and_kernel_hazards(self):
        bad = ["", "x" * 16, "0tun", "tun 0", "tun0;reboot", "tun0 && id", "tun/0", "tun:0",
               "tun0\n", "tün0", "..", "$(id)", "-tun"]
        for name in bad:
            with self.subTest(name=name), self.assertRaises(TunError):
                validate_name(name)

    def test_name_rejects_non_strings(self):
        for value in (None, 0, ["tun0"], b"tun0"):
            with self.subTest(value=value), self.assertRaises(TunError):
                validate_name(value)

    def test_address_needs_cidr_and_usable_host(self):
        self.assertEqual(str(validate_address("10.8.0.1/24")), "10.8.0.1/24")
        bad = ["10.8.0.1", "10.8.0.1/31", "10.8.0.1/7", "0.0.0.0/24", "224.0.0.1/24",
               "127.0.0.1/8", "10.8.0.300/24", "10.8.0.1/24; id", "fd00::1/64", "10.8.0.255/24", ""]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(TunError):
                validate_address(text)

    def test_mtu_bounds(self):
        self.assertEqual(validate_mtu(1400), 1400)
        self.assertEqual(validate_mtu(576), 576)
        for bad in (575, 1401, 0, -1, True, "1400", 1400.0, None):
            with self.subTest(mtu=bad), self.assertRaises(TunError):
                validate_mtu(bad)

    def test_route_accepts_prefixes_and_refuses_default(self):
        self.assertEqual(str(validate_route("10.8.0.0/24")), "10.8.0.0/24")
        for bad in ("0.0.0.0/0", "10.8.0.1/24", "10.8.0.0", "10.8.0.0/33", "::/0", "10.8.0.0/24 x"):
            with self.subTest(route=bad), self.assertRaises(TunError):
                validate_route(bad)


class CommandTests(unittest.TestCase):
    def test_argument_lists_for_a_full_setup(self):
        cmds = build_ip_commands("ioessa0", "10.8.0.1/24", 1400, ["10.9.0.0/16"])
        self.assertEqual(cmds, [
            ["addr", "add", "10.8.0.1/24", "dev", "ioessa0"],
            ["link", "set", "dev", "ioessa0", "mtu", "1400"],
            ["link", "set", "dev", "ioessa0", "up"],
            ["route", "add", "10.9.0.0/16", "dev", "ioessa0"],
        ])

    def test_route_equal_to_connected_network_is_skipped(self):
        # `ip addr add 10.8.0.2/24` already installs 10.8.0.0/24; a second add fails with EEXIST.
        cmds = build_ip_commands("ioessa0", "10.8.0.2/24", 1400, ["10.8.0.0/24"])
        self.assertFalse([c for c in cmds if c[0] == "route"])

    def test_every_argument_is_a_plain_string(self):
        cmds = build_ip_commands("ioessa0", "10.8.0.1/24", 1400, ["10.9.0.0/16"])
        for argv in cmds:
            for arg in argv:
                self.assertIsInstance(arg, str)
                self.assertNotIn(";", arg)
                self.assertNotIn(" ", arg)

    def test_invalid_input_builds_nothing(self):
        with self.assertRaises(TunError):
            build_ip_commands("ioessa0; id", "10.8.0.1/24", 1400)
        with self.assertRaises(TunError):
            build_ip_commands("ioessa0", "10.8.0.1/24", 1500)   # above MAX_INNER

    def test_run_ip_uses_argument_list_without_shell(self):
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with mock.patch("tun_linux.shutil.which", return_value="/sbin/ip"), \
             mock.patch("tun_linux.subprocess.run", return_value=done) as run:
            _run_ip(["link", "set", "dev", "ioessa0", "up"])
        argv = run.call_args[0][0]
        self.assertEqual(argv, ["/sbin/ip", "link", "set", "dev", "ioessa0", "up"])
        self.assertIsInstance(argv, list)
        self.assertFalse(run.call_args[1].get("shell", False))

    def test_run_ip_reports_stderr_on_failure(self):
        failed = subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="RTNETLINK answers: File exists")
        with mock.patch("tun_linux.shutil.which", return_value="/sbin/ip"), \
             mock.patch("tun_linux.subprocess.run", return_value=failed):
            with self.assertRaises(TunError) as cm:
                _run_ip(["route", "add", "10.9.0.0/16", "dev", "ioessa0"])
        self.assertIn("File exists", str(cm.exception))

    def test_configure_validates_before_running_anything(self):
        dev = object.__new__(LinuxTun)          # skip __init__: no device is opened
        dev.name, dev._fd = "ioessa0", None
        with mock.patch("tun_linux._run_ip") as run:
            with self.assertRaises(TunError):
                dev.configure("10.8.0.1/24", 9999)
            with self.assertRaises(TunError):
                dev.configure("10.8.0.1/24", 1400, ["0.0.0.0/0"])
        run.assert_not_called()

    def test_configure_runs_commands_in_order(self):
        dev = object.__new__(LinuxTun)
        dev.name, dev._fd = "ioessa0", None
        with mock.patch("tun_linux._run_ip") as run:
            dev.configure("10.8.0.1/24", 1400, ["10.9.0.0/16"])
        self.assertEqual([c.args[0][0] for c in run.call_args_list], ["addr", "link", "link", "route"])


class MtuMathTests(unittest.TestCase):
    def test_overhead_is_the_sum_of_real_sizes(self):
        # Outer IPv4 20 + UDP 8 + DATA header 16 + padding 0..3 + trailer 2 + tag 16 = 65
        self.assertEqual(IPV4_HDR, 20)
        self.assertEqual(UDP_HDR, 8)
        self.assertEqual(DATA_HDR_LEN, 16)
        self.assertEqual(TAG_LEN, 16)
        self.assertEqual(tunnel_overhead(), 65)

    def test_default_mtu_fits_both_limits(self):
        self.assertEqual(max_tun_mtu(1500), 1400)           # capped by MAX_INNER
        self.assertEqual(DEFAULT_MTU, 1400)
        self.assertLessEqual(DEFAULT_MTU, MAX_INNER)
        self.assertLessEqual(DEFAULT_MTU + tunnel_overhead(), 1500)

    def test_small_link_lowers_the_mtu(self):
        self.assertEqual(max_tun_mtu(1400), 1335)           # 1400 - 65
        self.assertEqual(max_tun_mtu(1280), 1215)

    def test_overhead_matches_packets_sealed_by_the_core(self):
        """Seal inner packets of every length from 20 to MAX_INNER and measure what goes on the
        wire. The UDP payload is the DATA message. Add the outer IPv4 and UDP headers to get the
        packet size on the link. Check that the measured worst case equals tunnel_overhead()."""
        a, b = handshake_local(psk=b"", addr_a=("127.0.0.1", 1), addr_b=("127.0.0.1", 2))
        a.peers[b.pub].spd = [Policy(ANY, PROTECT)]
        peer = a.peers[b.pub]
        worst, least = 0, 10**9
        for inner_len in range(20, MAX_INNER + 1):
            inner = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x" * (inner_len - 20))
            pkt, _ = a.send(peer, inner)
            extra = len(pkt) - inner_len
            worst, least = max(worst, extra), min(least, extra)
        self.assertEqual(least, 34)                          # 16 + 0 + 2 + 16
        self.assertEqual(worst, 37)                          # 16 + 3 + 2 + 16
        self.assertEqual(worst + IPV4_HDR + UDP_HDR, tunnel_overhead())
        # On a 1500-byte link, a full-size inner packet still fits after encapsulation.
        self.assertLessEqual(MAX_INNER + tunnel_overhead(), 1500)


class KernelConstantTests(unittest.TestCase):
    def test_tunsetiff_is_iow_t_202_int(self):
        # linux/if_tun.h: #define TUNSETIFF _IOW('T', 202, int). sizeof(int) is 4 on Linux.
        self.assertEqual(TUNSETIFF, _IOW("T", 202, 4))
        self.assertEqual(TUNSETIFF, 0x400454CA)

    def test_flags(self):
        self.assertEqual(IFF_TUN, 0x0001)      # layer 3, not IFF_TAP (0x0002)
        self.assertEqual(IFF_NO_PI, 0x1000)    # no packet-info prefix
        self.assertEqual(IFNAMSIZ, 16)

    def test_ifreq_layout(self):
        # struct ifreq: char ifr_name[16]; union (24 bytes on 64-bit); flags at offset 16.
        self.assertEqual(IFREQ.size, 40)
        buf = IFREQ.pack(b"ioessa0", IFF_TUN | IFF_NO_PI)
        self.assertEqual(len(buf), 40)
        self.assertEqual(buf[:16], b"ioessa0" + bytes(9))              # name, NUL padded
        self.assertEqual(struct.unpack_from("H", buf, 16)[0], 0x1001)  # flags at offset 16

    def test_device_path(self):
        self.assertEqual(CLONE_DEVICE, "/dev/net/tun")


class PlatformTests(unittest.TestCase):
    def test_bad_name_is_refused_on_every_platform(self):
        # On Windows the platform check fails first; on Linux the name check does. Either way
        # the call raises TunError and never touches the device.
        with self.assertRaises(TunError):
            LinuxTun("tun0; id")

    @unittest.skipIf(sys.platform == "linux", "checks the non-Linux refusal only")
    def test_off_linux_the_error_is_clear(self):
        with mock.patch("tun_linux.os.open") as opener:
            with self.assertRaises(TunError) as cm:
                LinuxTun("ioessa0")
        opener.assert_not_called()
        self.assertIn("Linux", str(cm.exception))

    def test_is_ipv4(self):
        self.assertTrue(is_ipv4(build_ipv4("10.8.0.2", "10.8.0.1", 253, b"hi")))
        self.assertFalse(is_ipv4(b"\x60" + bytes(39)))        # IPv6 version nibble
        self.assertFalse(is_ipv4(b"\x45" + bytes(5)))         # too short


class SocketTun(TunDevice):
    """Stands in for a TUN device. The loops see `dev` (a socket, so select() works), and the test
    uses `host` as the host's stack: host.send() is a packet the OS sends, host.recv() is a
    packet the OS receives. Works on any platform."""

    def __init__(self):
        # A connected UDP pair, not socketpair(): on Windows socketpair() is a byte stream, which
        # would merge two packets into one read. UDP keeps packet boundaries on every platform.
        self.dev = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.host = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dev.bind(("127.0.0.1", 0))
        self.host.bind(("127.0.0.1", 0))
        self.dev.connect(self.host.getsockname())
        self.host.connect(self.dev.getsockname())
        self.host.settimeout(3.0)

    def fileno(self) -> int:
        return self.dev.fileno()

    def read_packet(self) -> bytes:
        return self.dev.recv(65535)

    def write_packet(self, pkt: bytes) -> None:
        self.dev.send(pkt)

    def close(self) -> None:
        self.dev.close()
        self.host.close()


def _tunnel_pair(server_sock, client_sock):
    """Handshake between two nodes whose endpoints are the real loopback sockets."""
    s_addr = server_sock.getsockname()
    c_addr = client_sock.getsockname()
    client, server = handshake_local(psk=b"", addr_a=c_addr, addr_b=s_addr)
    client.peers[server.pub].spd = [Policy(ANY, PROTECT)]
    server.peers[client.pub].spd = [Policy(ANY, PROTECT)]
    return client, server, s_addr


class TunLoopTests(unittest.TestCase):
    """serve_tun and run_tun, end to end over loopback UDP. Each loop runs in a thread and
    returns after an idle period, so the tests end on their own."""

    def _udp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(0.05)
        return s

    def test_host_packet_crosses_the_tunnel_both_ways(self):
        srv_sock, cli_sock = self._udp(), self._udp()
        client, server, s_addr = _tunnel_pair(srv_sock, cli_sock)
        srv_tun, cli_tun = SocketTun(), SocketTun()
        srv_thread = threading.Thread(target=vpn_server.serve_tun, daemon=True, args=(
            srv_sock, server, srv_tun, 1.5, lambda s: None, 0.05))
        srv_thread.start()

        # Client -> server: the host sends a packet into the TUN device.
        to_server = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"from client through TUN")
        cli_tun.host.send(to_server)
        # Server -> client: the server host sends its reply through its own TUN device.
        reply = build_ipv4("10.8.0.1", "10.8.0.2", 253, b"reply through TUN")

        def inject_reply():
            srv_tun.host.send(reply)

        # Run the client loop in this thread; the reply is injected after the server has
        # the client's packet, so the server can route it back.
        timer = threading.Timer(0.4, inject_reply)
        timer.start()
        vpn_client.run_tun(cli_sock, client, client.peers[server.pub], s_addr, cli_tun,
                           timeout=2.0, idle_timeout=1.5, out=lambda s: None, tick=0.05)
        timer.join()
        srv_thread.join(timeout=5)

        self.assertEqual(srv_tun.host.recv(65535), to_server)
        self.assertEqual(cli_tun.host.recv(65535), reply)
        for s in (srv_sock, cli_sock):
            s.close()
        srv_tun.close()
        cli_tun.close()

    def test_non_ipv4_frames_stay_out_of_the_tunnel(self):
        srv_sock, cli_sock = self._udp(), self._udp()
        client, server, s_addr = _tunnel_pair(srv_sock, cli_sock)
        srv_tun, cli_tun = SocketTun(), SocketTun()
        srv_thread = threading.Thread(target=vpn_server.serve_tun, daemon=True, args=(
            srv_sock, server, srv_tun, 1.5, lambda s: None, 0.05))
        srv_thread.start()
        ipv6_frame = b"\x60" + bytes(39)                    # not IPv4: must be dropped
        ipv4 = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"only this one")
        cli_tun.host.send(ipv6_frame)
        cli_tun.host.send(ipv4)
        vpn_client.run_tun(cli_sock, client, client.peers[server.pub], s_addr, cli_tun,
                           timeout=2.0, idle_timeout=1.5, out=lambda s: None, tick=0.05)
        srv_thread.join(timeout=5)
        self.assertEqual(srv_tun.host.recv(65535), ipv4)
        with self.assertRaises(socket.timeout):              # nothing else arrived
            srv_tun.host.recv(65535)
        for s in (srv_sock, cli_sock):
            s.close()
        srv_tun.close()
        cli_tun.close()

    def test_authenticated_non_ipv4_inner_is_not_written_to_device(self):
        # A peer can authenticate and still send a non-IPv4 inner datagram. The receive side must
        # keep it out of the TUN device, as the send side does.
        srv_sock, cli_sock = self._udp(), self._udp()
        client, server, s_addr = _tunnel_pair(srv_sock, cli_sock)
        srv_tun = SocketTun()
        srv_tun.host.settimeout(0.3)
        events = []
        cli_peer = client.peers[server.pub]
        # IPv6-looking inner, sealed. Its bytes 12-16 are inside the default allowed_ips, so the
        # source check passes and the IPv4 check is what drops it.
        pkt, dst = client.send(cli_peer, b"\x60" + bytes(11) + bytes([10, 8, 0, 2]) + bytes(24))
        cli_sock.sendto(pkt, dst)
        vpn_server.serve_tun(srv_sock, server, srv_tun, idle_timeout=0.5, out=events.append, tick=0.05)
        with self.assertRaises(socket.timeout):
            srv_tun.host.recv(65535)
        self.assertTrue(any("not IPv4" in e for e in events), events)
        for s in (srv_sock, cli_sock):
            s.close()
        srv_tun.close()

    def test_server_drops_packets_with_no_matching_peer(self):
        srv_sock = self._udp()
        node = Node(new_private_key())            # no peers at all
        srv_tun = SocketTun()
        events = []
        srv_tun.host.send(build_ipv4("10.8.0.1", "10.8.0.2", 253, b"nobody"))
        vpn_server.serve_tun(srv_sock, node, srv_tun, idle_timeout=0.3, out=events.append, tick=0.05)
        self.assertTrue(any("no peer" in e for e in events), events)
        srv_sock.close()
        srv_tun.close()


class PrivilegeDropTests(unittest.TestCase):
    """drop_privileges (tun_linux): refuses a start that is not root and a drop to root, drops in
    order, and checks that the process cannot become root again. The OS calls are replaced, so this
    runs on any platform."""

    def _drop(self, euid=0, pw_uid=1000, can_regain=False, missing=False):
        state = {"uid": euid, "euid": euid, "calls": []}

        def setuid(uid):
            state["calls"].append(("setuid", uid))
            if uid == 0 and not can_regain:
                raise PermissionError(1, "Operation not permitted")
            state["uid"] = state["euid"] = uid

        def getpwnam(name):
            if missing:
                raise KeyError(name)
            return types.SimpleNamespace(pw_uid=pw_uid, pw_gid=1000)

        patches = [
            mock.patch.object(tun_linux.os, "name", "posix"),
            mock.patch.object(tun_linux.os, "geteuid", lambda: state["euid"], create=True),
            mock.patch.object(tun_linux.os, "getuid", lambda: state["uid"], create=True),
            mock.patch.object(tun_linux.os, "setuid", setuid, create=True),
            mock.patch.object(tun_linux.os, "setgid", lambda gid: state["calls"].append(("setgid", gid)), create=True),
            mock.patch.object(tun_linux.os, "setgroups", lambda gs: state["calls"].append(("setgroups", list(gs))),
                              create=True),
            mock.patch.dict(sys.modules, {"pwd": types.SimpleNamespace(getpwnam=getpwnam)}),
        ]
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            try:
                tun_linux.drop_privileges("svc")
                error = None
            except tun_linux.TunError as e:
                error = e
        return state, error

    def test_refuses_to_start_unless_root(self):
        state, error = self._drop(euid=1000)
        self.assertIsNotNone(error)
        self.assertEqual(state["calls"], [])

    def test_refuses_to_drop_to_root(self):
        state, error = self._drop(pw_uid=0)
        self.assertIn("root", str(error))
        self.assertEqual(state["calls"], [])

    def test_unknown_user_is_refused(self):
        state, error = self._drop(missing=True)
        self.assertIn("no such user", str(error))
        self.assertEqual(state["calls"], [])

    def test_drops_supplementary_groups_then_gid_then_uid(self):
        state, error = self._drop()
        self.assertIsNone(error)
        self.assertEqual(state["calls"][:3], [("setgroups", []), ("setgid", 1000), ("setuid", 1000)])
        self.assertEqual(state["uid"], 1000)

    def test_regaining_root_is_refused(self):
        state, error = self._drop(can_regain=True)
        self.assertIsNotNone(error)
        self.assertIn("undone", str(error))

if __name__ == "__main__":
    unittest.main()
