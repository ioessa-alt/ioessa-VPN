"""Leak test: a short handshake and some traffic over loopback, then checks on the captures of
that run only (outer = wire ciphertext, inner = plaintext on the TUN side).

Checked:
  * the test marker never appears in an outer capture (either endpoint), but does appear in the
    inner captures, so the marker check is known to be able to see plaintext
  * the initiator's static public key does not appear in plaintext on the wire: not in any
    cleartext field, and not in any payload byte
  * the message types and lengths match the protocol in vpn_constants.py (INIT 1236, RESP 1180,
    COOKIE 72, DATA = header + padded plaintext + tag)
  * both endpoints saw the same datagrams in the same order (checks the hook)

Keys are generated in memory and never written out. The capture directory is temporary and is
deleted when the tests finish.
"""
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TUNNEL = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, TUNNEL)

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

import analyze  # noqa: E402
import vpn_client  # noqa: E402
import vpn_server  # noqa: E402
from analyze import analyze as run_analyze  # noqa: E402
from tap import CaptureSink, TappedSocket, tap_node, OUTER_NAME, INNER_NAME  # noqa: E402
from vpn_constants import (COOKIE_LEN, DATA_HDR_LEN, INIT_LEN, MSG_COOKIE, MSG_DATA, MSG_INIT,  # noqa: E402
                           MSG_RESP, RESP_LEN, TAG_LEN)
from vpn_ip import build_ipv4, BYPASS, Policy, PROTECT  # noqa: E402
from vpn_node import Node  # noqa: E402
from pcap import read_pcap  # noqa: E402
import ipaddress  # noqa: E402

MARKER = b"LEAKTEST-PLAINTEXT-MARKER-8f2c1d"
PACKETS = 3


def _pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _bound_udp() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    return s


def run_session(outdir: str, packets: int = PACKETS) -> dict:
    """Handshake, send `packets` marked datagrams, read the echoes. Both sides are tapped."""
    cli_priv, srv_priv = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    cli_pub, srv_pub = _pub(cli_priv), _pub(srv_priv)
    cli_node = Node(cli_priv, b"")
    srv_node = Node(srv_priv, b"")
    srv_peer = srv_node.add_peer(cli_pub, endpoint=None, keepalive=None, kem_pub=cli_node.kem_pub)
    srv_peer.spd = [Policy(ipaddress.IPv4Network("0.0.0.0/0"), PROTECT)]
    cli_peer = cli_node.add_peer(srv_pub, endpoint=None, keepalive=None, kem_pub=srv_node.kem_pub)
    cli_peer.spd = [Policy(ipaddress.IPv4Network("10.8.0.0/24"), PROTECT),
                    Policy(ipaddress.IPv4Network("0.0.0.0/0"), BYPASS)]

    srv_sink = CaptureSink(os.path.join(outdir, "server"))
    cli_sink = CaptureSink(os.path.join(outdir, "client"))
    srv_raw, cli_raw = _bound_udp(), _bound_udp()
    srv_addr = srv_raw.getsockname()
    srv_sock = TappedSocket(srv_raw, srv_sink)
    cli_sock = TappedSocket(cli_raw, cli_sink)
    tap_node(srv_node, srv_sink)
    tap_node(cli_node, cli_sink)
    cli_peer.endpoint = srv_addr

    server_out, client_out = [], []
    server_err = []

    def serve() -> None:
        try:
            vpn_server.serve(srv_sock, srv_node, idle_timeout=2.0, echo=True,
                             out=server_out.append, tick=0.2)
        except Exception as e:                       # surfaced by the test, not swallowed
            server_err.append(repr(e))

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    echoes = []
    try:
        vpn_client.handshake(cli_sock, cli_node, cli_peer, srv_addr, 10.0, out=client_out.append)
        for i in range(packets):
            inner = build_ipv4("10.8.0.2", "10.8.0.1", 253, MARKER + f" #{i}".encode())
            vpn_client.send_inner(cli_sock, cli_node, cli_peer, srv_addr, inner, 10.0, out=client_out.append)
            reply = vpn_client._recv_from(cli_sock, srv_addr, 10.0)
            act = cli_node.handle(reply, srv_addr, time.monotonic())
            vpn_client._send_all(cli_sock, act.send)
            if act.inner:
                echoes.append(act.inner)
    finally:
        th.join(timeout=30)
        for sink in (srv_sink, cli_sink):
            sink.close()
        srv_raw.close()
        cli_raw.close()
    return {
        "cli_pub": cli_pub, "srv_pub": srv_pub,
        "server_outer": os.path.join(outdir, "server", OUTER_NAME),
        "server_inner": os.path.join(outdir, "server", INNER_NAME),
        "client_outer": os.path.join(outdir, "client", OUTER_NAME),
        "client_inner": os.path.join(outdir, "client", INNER_NAME),
        "handshake_ok": cli_peer.current is not None and srv_peer.current is not None,
        "echoes": echoes, "server_err": server_err, "server_out": server_out, "client_out": client_out,
    }


class LeakTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.session = run_session(cls._tmp.name)
        r = cls.session
        cls.srv_rep = run_analyze(r["server_outer"], markers=[MARKER], static_pubs=[r["cli_pub"], r["srv_pub"]])
        cls.cli_rep = run_analyze(r["client_outer"], markers=[MARKER], static_pubs=[r["cli_pub"], r["srv_pub"]])
        cls.raw = {}
        for k in ("server_outer", "client_outer"):
            with open(r[k], "rb") as f:
                cls.raw[k] = f.read()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_session_actually_ran(self):
        self.assertEqual(self.session["server_err"], [], "server thread raised")
        self.assertTrue(self.session["handshake_ok"], "handshake did not complete")
        self.assertEqual(len(self.session["echoes"]), PACKETS)
        for echo in self.session["echoes"]:
            self.assertIn(MARKER, echo)          # the echo is decrypted plaintext on the client

    def test_marker_absent_from_outer_captures(self):
        for name, raw in self.raw.items():
            self.assertNotIn(MARKER, raw, f"marker found in {name}")
        self.assertEqual(self.srv_rep.marker_in_payload, [])
        self.assertEqual(self.cli_rep.marker_in_payload, [])
        self.assertEqual(self.srv_rep.marker_in_cleartext, [])
        self.assertEqual(self.cli_rep.marker_in_cleartext, [])

    def test_marker_present_in_inner_captures_as_a_control(self):
        for key in ("server_inner", "client_inner"):
            pf = read_pcap(self.session[key])
            self.assertTrue(any(MARKER in rec.data for rec in pf.records), f"no plaintext marker in {key}")

    def test_initiator_static_key_not_in_plaintext(self):
        cli_pub = self.session["cli_pub"]
        for name, raw in self.raw.items():
            self.assertNotIn(cli_pub, raw, f"client static public key appears in {name}")
        for rep in (self.srv_rep, self.cli_rep):
            self.assertEqual(rep.key_equal_cleartext, [])
            self.assertEqual(rep.key_in_payload, [])

    def test_responder_static_key_not_in_plaintext_either(self):
        for name, raw in self.raw.items():
            self.assertNotIn(self.session["srv_pub"], raw, f"server static public key appears in {name}")

    def test_message_types_and_lengths_match_vpn_constants(self):
        self.assertEqual(analyze.SPEC_LEN, {MSG_INIT: INIT_LEN, MSG_RESP: RESP_LEN, MSG_COOKIE: COOKIE_LEN})
        for rep in (self.srv_rep, self.cli_rep):
            self.assertEqual(rep.format_problems, [])
            self.assertEqual(rep.findings, [])
            types = {m.mtype for m in rep.messages}
            self.assertLessEqual(types, {MSG_INIT, MSG_RESP, MSG_DATA})
            self.assertIn(MSG_INIT, types)
            self.assertIn(MSG_RESP, types)
            self.assertEqual(rep.messages[0].mtype, MSG_INIT)
            self.assertEqual(rep.messages[0].length, INIT_LEN)
            for m in rep.messages:
                if m.mtype == MSG_RESP:
                    self.assertEqual(m.length, RESP_LEN)
                if m.mtype == MSG_DATA:
                    body = m.length - DATA_HDR_LEN - TAG_LEN       # padded plaintext, incl. trailer
                    self.assertGreaterEqual(body, 4)
                    self.assertEqual(body % 4, 0, "DATA plaintext is not padded to a multiple of 4")

    def test_both_endpoints_saw_the_same_datagrams(self):
        cli = self.cli_rep.messages
        srv = self.srv_rep.messages
        cli_addr = self.cli_rep.messages[0].src
        sent_by_client = [m.payload for m in cli if m.src == cli_addr]
        received_by_server = [m.payload for m in srv if m.src == cli_addr]
        self.assertEqual(sent_by_client, received_by_server)
        sent_by_server = [m.payload for m in srv if m.src != cli_addr]
        received_by_client = [m.payload for m in cli if m.src != cli_addr]
        self.assertEqual(sent_by_server, received_by_client)


if __name__ == "__main__":
    unittest.main()
