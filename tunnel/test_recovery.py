"""Open issue 63: recovery paths that were not tested before.

- A server restart, followed by a rekey from the client (the old session is gone, a new handshake
  must complete and carry data).
- A server rebuilt from an empty peer list, then the peer added back.

The exchange runs through the real message handlers, with the same clock, so no state is faked.
"""
import unittest

from vpn_ip import build_ipv4

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from test_vpn import A_ADDR, B_ADDR, PROTECT_ALL, FakeClock
from vpn_constants import REKEY_TIMEOUT
from vpn_node import Node

INNER = build_ipv4("10.8.0.2", "10.8.0.1", 253, b"x" * 20)      # a 40-byte IPv4 header-sized datagram


def pair_without_handshake(clk):
    """Two configured nodes with no handshake yet, so the test controls when each one happens."""
    a = Node(X25519PrivateKey.generate(), clock=clk)
    b = Node(X25519PrivateKey.generate(), clock=clk)
    pa = a.add_peer(b.pub, B_ADDR, kem_pub=b.kem_pub)
    a.peers[b.pub].spd = list(PROTECT_ALL)
    b.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub).spd = list(PROTECT_ALL)
    return a, b, pa


def handshake(a: Node, b: Node, pa, now: float) -> None:
    """Run INIT and RESP between a and b. Asserts that both sides see the handshake complete."""
    (init, _), = a.initiate(pa, now)
    act = b.handle(init, A_ADDR, now)
    assert act.send, act.events
    (resp, _), = act.send
    a.handle(resp, B_ADDR, now)
    assert pa.current is not None


def new_server_like(old: Node, peers) -> Node:
    """A server process that starts again with the same keys and no sessions (a restart)."""
    b = Node(old._priv, kem_priv=old._kem_priv, clock=old.clock)
    for pub, endpoint, kem_pub in peers:
        b.add_peer(pub, endpoint, kem_pub=kem_pub)
    return b


class RestartThenRekeyTests(unittest.TestCase):

    def test_client_rekeys_after_server_restart_and_data_flows(self):
        clk = FakeClock(1000.0)
        a, b, pa = pair_without_handshake(clk)
        handshake(a, b, pa, clk.t)
        pkt, _ = a.send(pa, INNER, clk.t)
        self.assertEqual(b.handle(pkt, A_ADDR, clk.t).inner, INNER)     # before the restart, data flows

        b2 = new_server_like(b, [(a.pub, A_ADDR, a.kem_pub)])           # the server restarts
        self.assertEqual(b2.handle(pkt, A_ADDR, clk.t).inner, None)     # the old session index is unknown

        later = clk.t + REKEY_TIMEOUT + 1
        handshake(a, b2, pa, later)                                     # the client rekeys
        pkt2, _ = a.send(pa, INNER, later)
        self.assertEqual(b2.handle(pkt2, A_ADDR, later).inner, INNER)


class EmptyPeerListTests(unittest.TestCase):

    def test_server_rebuilt_with_no_peers_refuses_then_accepts_after_re_add(self):
        clk = FakeClock(1000.0)
        a, b, pa = pair_without_handshake(clk)
        b_empty = Node(b._priv, kem_priv=b._kem_priv, clock=clk)       # no peers at all
        (init, _), = a.initiate(pa, clk.t)
        act = b_empty.handle(init, A_ADDR, clk.t)
        self.assertEqual(act.send, [])                                  # silent, as for any unknown key
        self.assertTrue(any("unknown peer key" in e for e in act.events), act.events)

        b_empty.add_peer(a.pub, A_ADDR, kem_pub=a.kem_pub)              # the operator adds the peer back
        later = clk.t + REKEY_TIMEOUT + 1
        handshake(a, b_empty, pa, later)
        pkt, _ = a.send(pa, INNER, later)
        self.assertEqual(b_empty.handle(pkt, A_ADDR, later).inner, INNER)


if __name__ == "__main__":
    unittest.main()
