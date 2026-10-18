"""Tests for the hardening gaps closed after ZERO_TRUST_REVIEW.md and SECURITY_ENGINEERING_REVIEW.md:
source-address claims, server-key overlap on the client, timers under load, key-file modes, and
the endpoint move on an unverified INIT. Run from this folder with: python -m unittest test_hardening
No admin rights. Keys are generated per run. The client tests use real loopback UDP sockets.
"""
import io
import ipaddress
import os
import random
import socket
import tempfile
import threading
import types
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from vpn_client import _bind, handshake_any
from vpn_constants import (MSG_INIT, MSG_RESP, REKEY_ATTEMPT_TIME, REKEY_RETRY_CAP, REKEY_TIMEOUT, SRC_INIT_BURST,
                           SRC_INIT_RATE, SRC_TABLE_MAX)
from vpn_crypto import encode_key
from vpn_keyfiles import _check_key_file_mode, _check_windows_acl, load_static_private
from vpn_ip import build_ipv4, BYPASS, Policy, PROTECT
from vpn_node import Action, Node
from vpn_server import serve
from test_vpn import A_ADDR, B_ADDR, PROTECT_ALL, FakeClock, FakeSock, pair, unfinished


def net(text: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(text)


def enroll(srv: Node, addr: tuple):
    """Create a client node and complete a handshake with `srv`, which sees the client at `addr`.
    Returns (client node, client's peer for the server, server's peer for the client)."""
    c = Node(X25519PrivateKey.generate())
    cp = c.add_peer(srv.pub, B_ADDR, kem_pub=srv.kem_pub)
    cp.spd = list(PROTECT_ALL)
    sp = srv.add_peer(c.pub, addr, kem_pub=c.kem_pub)
    (init, _), = c.initiate(cp)
    (resp, _), = srv.handle(init, addr).send
    for pkt, _dst in c.handle(resp, B_ADDR).send:
        srv.handle(pkt, addr)
    return c, cp, sp


class SourceClaimTests(unittest.TestCase):
    """Gap 1: an inner source address belongs to the one peer whose allowed-IP list covers it."""

    def test_claimed_source_is_refused_and_endpoint_does_not_move(self):
        srv = Node(X25519PrivateKey.generate())
        c1, cp1, sp1 = enroll(srv, A_ADDR)
        c2, cp2, sp2 = enroll(srv, ("127.0.0.1", 3))
        sp1.allowed_ips = [net("10.8.0.2/32")]
        sp2.allowed_ips = [net("10.8.0.3/32")]

        wire, _ = c1.send(cp1, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"own address"))
        self.assertIsNotNone(srv.handle(wire, A_ADDR).inner)          # the owner is accepted

        # Peer 2 sends with peer 1's address, from a new address. Authenticated, but refused, and
        # the endpoint stays where it was.
        wire, _ = c2.send(cp2, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"claim"))
        act = srv.handle(wire, ("127.0.0.1", 4))
        self.assertIsNone(act.inner)
        self.assertTrue(any("source not allowed" in e for e in act.events), act.events)
        self.assertEqual(sp2.endpoint, ("127.0.0.1", 3))
        self.assertEqual(sp1.endpoint, A_ADDR)

    def test_refused_packet_does_not_promote_or_roam(self):
        srv = Node(X25519PrivateKey.generate())
        c1, cp1, sp1 = enroll(srv, A_ADDR)
        sp1.allowed_ips = [net("10.8.0.2/32")]
        wire, _ = c1.send(cp1, build_ipv4("10.8.0.9", "10.8.0.1", 253, b"not mine"))
        act = srv.handle(wire, ("198.51.100.7", 7))
        self.assertIsNone(act.inner)
        self.assertEqual(sp1.endpoint, A_ADDR)

    def test_overlapping_allowed_ips_are_detected_without_printing_keys(self):
        srv = Node(X25519PrivateKey.generate())
        c1, _, sp1 = enroll(srv, A_ADDR)
        c2, _, sp2 = enroll(srv, ("127.0.0.1", 3))
        sp1.allowed_ips = [net("10.8.0.0/24")]
        sp2.allowed_ips = [net("10.8.0.0/24")]
        with self.assertRaises(ValueError) as cm:
            srv.check_allowed_ips_disjoint()
        msg = str(cm.exception)
        self.assertIn("10.8.0.0/24", msg)
        self.assertNotIn(encode_key(c1.pub), msg)
        self.assertNotIn(encode_key(c2.pub), msg)
        sp2.allowed_ips = [net("10.8.1.0/24")]
        srv.check_allowed_ips_disjoint()                  # disjoint lists pass

    def test_single_peer_with_any_source_passes_the_check(self):
        srv = Node(X25519PrivateKey.generate())
        enroll(srv, A_ADDR)
        srv.check_allowed_ips_disjoint()


class EndpointOnInitTests(unittest.TestCase):
    """Gap 5: a replayed INIT from another address cannot move the endpoint, because the replayer
    lacks the session keys. The endpoint moves on the first authenticated packet of the new session."""

    def test_replayed_init_after_restart_does_not_move_endpoint(self):
        a = Node(X25519PrivateKey.generate())
        b = Node(X25519PrivateKey.generate())
        pa = a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
        b.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
        (init, _), = a.initiate(pa)
        (resp, _), = b.handle(init, A_ADDR).send
        for pkt, _dst in a.handle(resp, B_ADDR).send:
            b.handle(pkt, A_ADDR)                        # tunnel up, endpoint is A_ADDR

        # A restarted responder has no replay state, so it accepts the captured INIT again.
        b2 = Node(b._priv, kem_priv=b._kem_priv)     # a restart keeps the same key files
        pb2 = b2.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
        attacker = ("203.0.113.5", 5)
        act = b2.handle(init, attacker)
        self.assertEqual(len(act.send), 1)               # the RESP goes back to the sender's address
        self.assertEqual(pb2.endpoint, A_ADDR)           # but the endpoint did not move

    def test_legitimate_new_session_moves_endpoint_on_first_data(self):
        a = Node(X25519PrivateKey.generate())
        b = Node(X25519PrivateKey.generate())
        pa = a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
        pa.spd = list(PROTECT_ALL)
        pb = b.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)
        pb.spd = list(PROTECT_ALL)
        (init, _), = a.initiate(pa)
        new_addr = ("127.0.0.1", 50001)                  # the initiator now sends from a new port
        (resp, _), = b.handle(init, new_addr).send
        self.assertEqual(pb.endpoint, A_ADDR)            # not moved by the INIT
        confirm = a.handle(resp, B_ADDR).send
        for pkt, _dst in confirm:
            b.handle(pkt, new_addr)                      # first authenticated data on the new session
        self.assertEqual(pb.endpoint, new_addr)
        wire, dst = b.send(pb, build_ipv4("10.8.0.1", "10.8.0.2", 253, b"reply"))
        self.assertEqual(dst, new_addr)


class TimersUnderLoadTests(unittest.TestCase):
    """Gap 3: timers run on a fixed schedule even when datagrams never let recvfrom time out."""

    class BusyNode:
        """Each clock() call advances time by 0.1 s, so 100 datagrams cover 10 s of simulated time."""

        def __init__(self):
            self.t = 0.0
            self.polls = 0

        def clock(self):
            self.t += 0.1
            return self.t

        def handle(self, data, addr, now=None):
            return Action()

        def poll(self, now=None):
            self.polls += 1
            return []

    def test_poll_runs_during_steady_traffic(self):
        node = self.BusyNode()
        sock = FakeSock([(b"x" * 8, A_ADDR)] * 100)      # then the socket times out and serve returns
        serve(sock, node, idle_timeout=None, out=lambda s: None, tick=1.0)
        self.assertGreaterEqual(node.polls, 8, node.polls)   # about one run per simulated second


class KeyFileModeTests(unittest.TestCase):
    """Gap 4: on POSIX a private key file that group or others can access is refused. On Windows,
    modes are not enforced, so the load goes on after a warning."""

    @staticmethod
    def _stat(mode):
        return lambda path: types.SimpleNamespace(st_mode=0o100000 | mode)

    def test_posix_owner_only_file_is_accepted(self):
        _check_key_file_mode("key", posix=True, stat=self._stat(0o600))

    def test_posix_group_or_world_access_is_refused(self):
        for mode in (0o644, 0o640, 0o604, 0o666):
            with self.subTest(mode=oct(mode)), self.assertRaises(RuntimeError) as cm:
                _check_key_file_mode("key", posix=True, stat=self._stat(mode))
            self.assertIn("chmod 600", str(cm.exception))

    @staticmethod
    def _icacls(stdout, returncode=0):
        """A stand-in for subprocess.run that returns fixed icacls output."""
        def run(args, **kwargs):
            return types.SimpleNamespace(stdout=stdout, returncode=returncode)
        return run

    KEY_PATH = r"C:\keys\alice.key"

    def test_windows_owner_system_and_admins_only_is_accepted(self):
        out = (f"{self.KEY_PATH} NT AUTHORITY\\SYSTEM:(I)(F)\n"
               f"                BUILTIN\\Administrators:(I)(F)\n"
               f"                DESKTOP-1\\alice:(I)(F)\n\n"
               "Successfully processed 1 files; Failed processing 0 files\n")
        _check_windows_acl(self.KEY_PATH, run=self._icacls(out), user="alice")

    def test_windows_other_principal_with_access_is_refused(self):
        out = (f"{self.KEY_PATH} DESKTOP-1\\alice:(F)\n"
               "                DESKTOP-1\\bob:(R)\n")
        with self.assertRaises(RuntimeError) as cm:
            _check_windows_acl(self.KEY_PATH, run=self._icacls(out), user="alice")
        self.assertIn("bob", str(cm.exception))

    def test_windows_everyone_with_access_is_refused(self):
        out = f"{self.KEY_PATH} Everyone:(R)\n"          # first ACE on the path's line
        with self.assertRaises(RuntimeError) as cm:
            _check_windows_acl(self.KEY_PATH, run=self._icacls(out), user="alice")
        self.assertIn("grants access to Everyone.", str(cm.exception))

    def test_windows_deny_entry_does_not_grant(self):
        out = (f"{self.KEY_PATH} DESKTOP-1\\alice:(F)\n"
               "                Everyone:(DENY)(R)\n")
        _check_windows_acl(self.KEY_PATH, run=self._icacls(out), user="alice")

    def test_windows_entry_with_no_rights_does_not_grant(self):
        out = (f"{self.KEY_PATH} DESKTOP-1\\alice:(F)\n"
               "                Guests:(N)\n")
        _check_windows_acl(self.KEY_PATH, run=self._icacls(out), user="alice")

    def test_windows_unreadable_acl_fails_closed(self):
        with self.assertRaises(RuntimeError):
            _check_windows_acl(self.KEY_PATH, run=self._icacls("", returncode=5), user="alice")
        with self.assertRaises(RuntimeError) as cm:
            _check_windows_acl(self.KEY_PATH, run=self._icacls("Successfully processed 1 files\n"), user="alice")
        self.assertIn("no ACL entries", str(cm.exception))

    def test_windows_missing_icacls_fails_closed(self):
        def run(args, **kwargs):
            raise FileNotFoundError("icacls")
        with self.assertRaises(RuntimeError):
            _check_windows_acl(self.KEY_PATH, run=run, user="alice")

    def test_windows_check_is_used_when_not_posix(self):
        with mock.patch("vpn_keyfiles._check_windows_acl") as check:
            _check_key_file_mode("key", posix=False, stat=self._stat(0o666))
        check.assert_called_once_with("key")

    def test_load_from_file_uses_the_check(self):
        priv = X25519PrivateKey.generate()
        raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(encode_key(raw) + "\n")
            with mock.patch("vpn_keyfiles._check_key_file_mode") as check:
                load_static_private(path)
            check.assert_called_once_with(path)
        finally:
            os.remove(path)


class ClientServerKeyTests(unittest.TestCase):
    """Gap 2: the client tries every configured server key and completes with the one that answers."""

    def _serve_in_thread(self, sock, node, idle):
        t = threading.Thread(target=serve, args=(sock, node, idle), kwargs={"out": lambda s: None, "tick": 0.1},
                             daemon=True)
        t.start()
        return t

    def test_client_completes_with_the_key_that_answers(self):
        srv = Node(X25519PrivateKey.generate())
        ssock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ssock.bind(("127.0.0.1", 0))
        srv_addr = ssock.getsockname()
        srv.add_peer(X25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw), None)         # an unrelated key on the server
        client = Node(X25519PrivateKey.generate())
        srv.add_peer(client.pub, None, kem_pub=client.kem_pub)
        wrong = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        candidates = [client.add_peer(wrong, srv_addr), client.add_peer(srv.pub, srv_addr, kem_pub=srv.kem_pub)]
        csock = _bind("127.0.0.1")
        t = self._serve_in_thread(ssock, srv, 2.0)
        try:
            peer = handshake_any(csock, client, candidates, srv_addr, timeout=5.0, out=lambda s: None)
        finally:
            csock.close()
            t.join(timeout=10)
            ssock.close()
        self.assertEqual(peer.pub, srv.pub)
        self.assertIsNotNone(peer.current)
        self.assertEqual(list(client.peers), [srv.pub])  # the other candidate was removed

    def test_no_matching_key_times_out(self):
        srv = Node(X25519PrivateKey.generate())
        ssock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ssock.bind(("127.0.0.1", 0))
        srv_addr = ssock.getsockname()
        client = Node(X25519PrivateKey.generate())
        srv.add_peer(client.pub, None, kem_pub=client.kem_pub)
        wrong = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        candidates = [client.add_peer(wrong, srv_addr)]
        csock = _bind("127.0.0.1")
        t = self._serve_in_thread(ssock, srv, 1.0)
        try:
            with self.assertRaises(socket.timeout):
                handshake_any(csock, client, candidates, srv_addr, timeout=0.6)
        finally:
            csock.close()
            t.join(timeout=10)
            ssock.close()


def _peer_pub() -> bytes:
    return X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _peer_kem_pub() -> bytes:
    return mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw()


class RetransmitBackoffTests(unittest.TestCase):
    """Gap 1 (RFC 7296 2.4, SRE review): retransmission gaps double from REKEY_TIMEOUT, are capped,
    carry jitter, and the whole attempt is bounded. The clock and the random source are injected,
    so nothing sleeps."""

    def _retry_times(self, rand, horizon=200.0):
        clk = FakeClock(1000.0)
        a = Node(X25519PrivateKey.generate(), clock=clk, rand=rand)
        pa = a.add_peer(_peer_pub(), B_ADDR, kem_pub=_peer_kem_pub())
        self.assertEqual(len(a.initiate(pa, clk.t)), 1)     # the first attempt is sent at once
        times = []
        while clk.t < 1000.0 + horizon:
            clk.t += 0.01
            if a.poll(clk.t):                               # dead server: only retransmissions
                times.append(clk.t - 1000.0)
        return times, pa

    def test_gaps_double_then_cap_and_attempt_is_bounded(self):
        times, pa = self._retry_times(lambda: 0.5)          # 0.5 is the jitter midpoint: no jitter
        gaps = [t2 - t1 for t1, t2 in zip([0.0] + times, times)]
        self.assertEqual(len(gaps), 5, times)
        for got, want in zip(gaps, [5.0, 10.0, 20.0, 20.0, 20.0]):
            self.assertAlmostEqual(got, want, delta=0.02)   # doubles, then holds at the cap
        self.assertLess(times[-1], REKEY_ATTEMPT_TIME)  # nothing is sent after the attempt limit
        self.assertIsNone(pa.pending)                        # the attempt is dropped in finite time
        self.assertIsNone(pa.current)

    def test_cap_value(self):
        a = Node(X25519PrivateKey.generate(), rand=lambda: 0.5)
        self.assertEqual(a._retry_interval(10), REKEY_RETRY_CAP)
        self.assertEqual(a._retry_interval(0), REKEY_TIMEOUT)

    def test_jitter_is_applied_to_every_gap(self):
        low, _ = self._retry_times(lambda: 0.0)              # -20 percent
        high, _ = self._retry_times(lambda: 0.999)           # +20 percent
        self.assertAlmostEqual(low[0], REKEY_TIMEOUT * 0.8, delta=0.02)
        self.assertAlmostEqual(high[0], REKEY_TIMEOUT * 1.2, delta=0.02)
        self.assertNotEqual(low[0], high[0])

    def test_random_jitter_stays_inside_the_band(self):
        rng = random.Random(7)
        times, pa = self._retry_times(rng.random)
        gaps = [t2 - t1 for t1, t2 in zip([0.0] + times, times)]
        base = [5.0, 10.0, 20.0, 20.0, 20.0]
        for got, b in zip(gaps, base):
            self.assertGreaterEqual(got, 0.8 * b - 0.02)
            self.assertLessEqual(got, 1.2 * b + 0.02)
        self.assertLess(times[-1], REKEY_ATTEMPT_TIME)
        self.assertIsNone(pa.pending)

    def test_first_attempt_is_unchanged(self):
        clk = FakeClock(1000.0)
        a = Node(X25519PrivateKey.generate(), clock=clk, rand=lambda: 0.999)
        pa = a.add_peer(_peer_pub(), B_ADDR, kem_pub=_peer_kem_pub())
        self.assertEqual(len(a.initiate(pa, clk.t)), 1)      # no delay before the first INIT


class SimultaneousRekeyTests(unittest.TestCase):
    """Gap 2 (RFC 7296 2.8.1): both peers start a rekey at the same instant. Each side holds both
    ephemeral keys, so the lower one wins with no extra round trip. The winner ignores the other INIT,
    the loser drops its attempt and answers, and both sides keep working."""

    def _collide(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pa, pb = a.peers[b.pub], b.peers[a.pub]
        a.rand = b.rand = lambda: 0.0                        # no jitter: both fire on the same poll
        wire, _ = a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x"), clk.t)
        b.handle(wire, A_ADDR, clk.t)
        wire, _ = b.send(pb, build_ipv4("10.8.0.1", "10.8.0.2", 253, b"y"), clk.t)
        a.handle(wire, B_ADDR, clk.t)
        clk.t += 121
        ia = [p for p, _ in a.poll(clk.t) if p[0] == MSG_INIT]
        ib = [p for p, _ in b.poll(clk.t) if p[0] == MSG_INIT]
        self.assertEqual(len(ia), 1)
        self.assertEqual(len(ib), 1)
        ra = b.handle(ia[0], A_ADDR, clk.t).send            # b sees a's INIT while its own is pending
        rb = a.handle(ib[0], B_ADDR, clk.t).send            # a sees b's INIT while its own is pending
        answers = [p for p, _ in ra + rb if p[0] == MSG_RESP]
        confirms = []
        for pkt, _ in ra:
            confirms += a.handle(pkt, B_ADDR, clk.t).send
        for pkt, _ in rb:
            confirms += b.handle(pkt, A_ADDR, clk.t).send
        for pkt, _ in confirms:
            b.handle(pkt, A_ADDR, clk.t)
            a.handle(pkt, B_ADDR, clk.t)
        return clk, a, b, pa, pb, answers

    def test_exactly_one_attempt_is_answered(self):
        _, a, b, pa, pb, answers = self._collide()
        self.assertEqual(len(answers), 1, "only the loser's peer INIT is answered; the winner ignores the other")
        self.assertIsNone(pa.pending)                        # both attempts are settled
        self.assertIsNone(pb.pending)

    def test_both_sides_can_send_and_receive_after_the_collision(self):
        for _ in range(6):
            clk, a, b, pa, pb, _ = self._collide()
            wire, _ = a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"from a"), clk.t)
            self.assertIsNotNone(b.handle(wire, A_ADDR, clk.t).inner)
            wire, _ = b.send(pb, build_ipv4("10.8.0.1", "10.8.0.2", 253, b"from b"), clk.t)
            self.assertIsNotNone(a.handle(wire, B_ADDR, clk.t).inner)

    def test_loser_leaves_no_session_from_its_own_attempt(self):
        """Each side ends with its current session and the pre-rekey session as previous, and
        nothing else. The attempt that lost never becomes a session on either side."""
        for _ in range(6):
            _, a, b, pa, pb, _ = self._collide()
            self.assertEqual(len(a.sessions), 2)
            self.assertEqual(len(b.sessions), 2)

    def test_due_rekey_waits_for_its_random_delay(self):
        clk = FakeClock(1000.0)
        a, b = pair(clock=clk)
        pa = a.peers[b.pub]
        a.rand = lambda: 0.5
        wire, _ = a.send(pa, build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x"), clk.t)
        b.handle(wire, A_ADDR, clk.t)
        clk.t += 121
        self.assertEqual(a.poll(clk.t), [])                  # due: the delay starts now
        self.assertEqual(a.poll(clk.t + 2.4), [])            # still inside the delay
        self.assertEqual(len([p for p, _ in a.poll(clk.t + 2.5) if p[0] == MSG_INIT]), 1)


class SourceBudgetTests(unittest.TestCase):
    """Per-source INIT budget (vpn_node `_source_budget`). A flood from one address is refused before
    any DH work. The table of buckets is bounded, so memory does not grow with attacker addresses."""

    def _node(self):
        return Node(X25519PrivateKey.generate(), clock=lambda: 0.0)

    def test_flood_from_one_source_is_refused_after_the_burst(self):
        node = self._node()
        src = ("198.51.100.7", 1000)
        results = [node._source_budget(src, 0.0) for _ in range(SRC_INIT_BURST + 5)]
        self.assertEqual(results.count(True), SRC_INIT_BURST)
        self.assertFalse(results[-1])

    def test_tokens_refill_at_the_configured_rate(self):
        node = self._node()
        src = ("198.51.100.7", 1000)
        for _ in range(SRC_INIT_BURST):
            node._source_budget(src, 0.0)                       # spend the burst
        self.assertFalse(node._source_budget(src, 0.0))
        allowed = [node._source_budget(src, 1.0) for _ in range(5)]   # one second later
        self.assertEqual(allowed.count(True), int(SRC_INIT_RATE))

    def test_other_sources_are_unaffected_by_a_flood(self):
        node = self._node()
        for _ in range(SRC_INIT_BURST + 5):
            node._source_budget(("198.51.100.7", 1000), 0.0)
        self.assertTrue(node._source_budget(("203.0.113.9", 2000), 0.0))

    def test_bucket_table_is_bounded(self):
        node = self._node()
        for i in range(SRC_TABLE_MAX + 100):
            node._source_budget((f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", 1), 0.0)
        self.assertLessEqual(len(node._src_buckets), SRC_TABLE_MAX)

    def test_a_normal_handshake_is_within_the_budget(self):
        a, b, pa, init = unfinished()
        self.assertEqual(len(b.handle(init, A_ADDR).send), 1)

if __name__ == "__main__":
    unittest.main()
