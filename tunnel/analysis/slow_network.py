"""Slow-network check (book Ch 11 topics: latency, loss, retransmission) over loopback.

Runs the real handshake code: vpn_client.handshake on the initiator and vpn_server.serve on the
responder. Both UDP sockets are wrapped in shim.LossyUDP, which drops datagrams and adds
latency. Each trial makes a new pair of keys (in memory only) and new sockets.

Per trial it measures: whether the first handshake completed, how long it took, how many INIT
messages the initiator sent (retransmissions show up here), and how many datagrams the shim
dropped. With --rekey it then runs a second handshake on the same peer, which is the rekey
path, and measures that too.

Timers are the protocol's own (vpn_constants: REKEY_TIMEOUT = 5 s between initiations, the
initiator's retransmit timer). They are not changed for this test. So a lost INIT costs
about one REKEY_TIMEOUT before the retransmission.

Usage:
  python analysis/slow_network.py --trials 30 --loss 0.10 --latency 0.0 --seed 1 --rekey
Prints one row per scenario. Exit status 0.
"""
import argparse
import math
import os
import random
import socket
import statistics
import sys
import threading
import time
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

import vpn_client  # noqa: E402
import vpn_server  # noqa: E402
from vpn_constants import MSG_INIT, REKEY_TIMEOUT  # noqa: E402
from vpn_node import Node  # noqa: E402
from shim import LossyUDP  # noqa: E402



def _loopback_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    return s


def run_trial(loss: float, latency: float, rng: random.Random, timeout: float, rekey: bool) -> Dict:
    """One handshake (and optionally one rekey) between two nodes over the lossy shim."""
    srv_priv = X25519PrivateKey.generate()
    cli_priv = X25519PrivateKey.generate()
    srv_node = Node(srv_priv, b"", clock=time.monotonic)
    cli_node = Node(cli_priv, b"", clock=time.monotonic)
    srv_node.add_peer(cli_node.pub, endpoint=None, keepalive=None, kem_pub=cli_node.kem_pub)
    cli_peer = cli_node.add_peer(srv_node.pub, endpoint=None, keepalive=None, kem_pub=srv_node.kem_pub)

    init_sends = [0]

    def count_init(data: bytes, _addr) -> None:
        if data and data[0] == MSG_INIT:
            init_sends[0] += 1

    srv_raw = _loopback_socket()
    srv_addr = srv_raw.getsockname()
    srv_sock = LossyUDP(srv_raw, rng, loss, latency)
    cli_raw = _loopback_socket()
    cli_sock = LossyUDP(cli_raw, rng, loss, latency, on_send=count_init)
    cli_peer.endpoint = srv_addr

    server_exit: List[str] = []

    # The responder is a daemon thread. Its idle exit is set past the longest time the client can
    # keep trying (its deadline, plus a rekey wait and one more deadline), so the responder never
    # closes its socket while the client is still sending. The real server runs until stopped.
    server_idle = 2 * timeout + 2 * REKEY_TIMEOUT

    def serve_then_close() -> None:
        try:
            vpn_server.serve(srv_sock, srv_node, idle_timeout=server_idle, echo=False,
                             out=lambda s: None, tick=0.2)
            server_exit.append("idle")
        except Exception as e:              # recorded, so a responder crash is not silent
            server_exit.append(repr(e))
            raise
        finally:
            srv_sock.close()

    threading.Thread(target=serve_then_close, daemon=True).start()

    res = {"ok": False, "secs": None, "init_sends": 0, "rekey_ok": None, "rekey_secs": None,
           "rekey_init_sends": 0}
    t0 = time.monotonic()
    try:
        vpn_client.handshake(cli_sock, cli_node, cli_peer, srv_addr, timeout, out=lambda s: None)
        res["ok"] = cli_peer.current is not None
    except socket.timeout:
        res["ok"] = False
    except ConnectionResetError as e:       # Windows: ICMP port-unreachable surfaces on recvfrom
        res["ok"] = False
        res["error"] = repr(e)
    res["secs"] = time.monotonic() - t0
    res["init_sends"] = init_sends[0]

    if rekey and res["ok"]:
        old = cli_peer.current
        # The protocol allows one INIT per REKEY_TIMEOUT (vpn_node.Node.initiate). Wait for that.
        if cli_peer.last_init_sent is not None:
            gap = REKEY_TIMEOUT - (time.monotonic() - cli_peer.last_init_sent)
            if gap > 0:
                time.sleep(gap)
        before = init_sends[0]
        t1 = time.monotonic()
        try:
            vpn_client.handshake(cli_sock, cli_node, cli_peer, srv_addr, timeout, out=lambda s: None)
            res["rekey_ok"] = cli_peer.current is not None and cli_peer.current is not old
        except socket.timeout:
            res["rekey_ok"] = False
        except ConnectionResetError as e:
            res["rekey_ok"] = False
            res["error"] = repr(e)
        res["rekey_secs"] = time.monotonic() - t1
        res["rekey_init_sends"] = init_sends[0] - before

    res["dropped"] = cli_sock.dropped_out + cli_sock.dropped_in + srv_sock.dropped_out + srv_sock.dropped_in
    res["server_exit"] = list(server_exit)   # may still be empty: the responder has not exited yet
    res["srv_rx"], res["srv_dropped_in"] = srv_sock.received, srv_sock.dropped_in
    res["cli_rx"], res["cli_dropped_in"] = cli_sock.received, cli_sock.dropped_in
    res["cli_dropped_out"], res["srv_dropped_out"] = cli_sock.dropped_out, srv_sock.dropped_out
    res["cli_sent"], res["srv_sent"] = cli_sock.sent, srv_sock.sent
    cli_sock.close()
    return res


def _stats(vals: List[float]) -> str:
    if not vals:
        return "-"
    return f"mean {statistics.mean(vals):.2f}  median {statistics.median(vals):.2f}  max {max(vals):.2f}"


def run(trials: int, loss: float, latency: float, seed: int, timeout: float, rekey: bool) -> str:
    rng = random.Random(seed)
    rows = [run_trial(loss, latency, rng, timeout, rekey) for _ in range(trials)]
    ok = [r for r in rows if r["ok"]]
    lines = [f"scenario: loss={loss:.0%} each direction, latency={latency * 1000:.0f} ms each direction, "
             f"seed={seed}, trials={trials}, timeout={timeout:g} s, REKEY_TIMEOUT={REKEY_TIMEOUT:g} s",
             f"  handshake completed: {len(ok)}/{trials}",
             f"  handshake seconds (all trials): {_stats([r['secs'] for r in rows])}",
             f"  handshake seconds (completed only): {_stats([r['secs'] for r in ok])}",
             f"  INIT sends per trial: mean {statistics.mean(r['init_sends'] for r in rows):.2f}, "
             f"max {max(r['init_sends'] for r in rows)}",
             f"  datagrams dropped by shim per trial: mean {statistics.mean(r['dropped'] for r in rows):.2f}",
             f"  trials ending in a socket error: {sum(1 for r in rows if 'error' in r)}"
             + (f" ({sorted({r['error'] for r in rows if 'error' in r})})" if any('error' in r for r in rows) else "")]
    if rekey:
        rk = [r for r in rows if r["rekey_ok"] is not None]
        rk_ok = [r for r in rk if r["rekey_ok"]]
        lines += [f"  rekey completed: {len(rk_ok)}/{len(rk)} (runs only after a completed handshake)",
                  f"  rekey seconds (completed only): {_stats([r['rekey_secs'] for r in rk_ok])}",
                  f"  rekey INIT sends per trial: mean "
                  f"{statistics.mean(r['rekey_init_sends'] for r in rk) if rk else math.nan:.2f}"]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Loss and latency check of the handshake on loopback")
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--loss", type=float, default=0.0, help="drop probability per datagram, each direction")
    ap.add_argument("--latency", type=float, default=0.0, help="one-way delay in seconds, each direction")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=30.0, help="per-handshake deadline in seconds")
    ap.add_argument("--rekey", action="store_true", help="also time a rekey after each completed handshake")
    args = ap.parse_args(argv)
    print(run(args.trials, args.loss, args.latency, args.seed, args.timeout, args.rekey), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
