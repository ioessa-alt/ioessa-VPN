"""VPN tunnel endpoint (UDP transport), WireGuard-style responder. See vpn_node.py.

Usage (PowerShell; keys come from env vars or files, never from source):
    $env:IOESSA_VPN_PRIVATE_KEY = "<base64 from vpn_keygen.py>"
    $env:IOESSA_VPN_PEER_PUBLIC_KEY = "<client public key, base64>"
    python vpn_server.py --port 4500                 # binds 127.0.0.1 by default

Options: --key-file / --peer-key-file read the keys from files instead; --use-psk enables the
optional pre-shared key (IOESSA_VPN_PSK) and must match on both ends. Standard library plus
`cryptography`. Binds loopback unless --bind is given.

Real TUN (Linux, root): --tun linux creates a TUN device with --tun-addr (default 10.8.0.1/24)
and --mtu (default 1400, see tun_linux.max_tun_mtu). Inner packets go into the host's stack, and
packets the host routes into the device are sent through the tunnel. The default --tun queue
keeps the in-memory echo demo that the tests use. See tun_linux.py and README.md.
"""
import argparse
import hashlib
import ipaddress
import math
import os
import select
import socket
import sys
import time
from typing import Callable, Optional

from peer_reload import PeerFileWatcher
from vpn_constants import DEFAULT_LOAD_THRESHOLD, KEEPALIVE_TIMEOUT, KEY_FILE_ENV, MAX_ESP, PROFILES, STATE_FILE_ENV
from vpn_errors import ESPError, RekeyRequired, StateFileError
from vpn_keyfiles import check_key_age, load_kem_private, load_peer_entries, load_psk, load_static_private
from vpn_state import default_state_path, state_key, TimestampStore
from vpn_ip import build_ipv4, describe, parse_ipv4, Policy, PROTECT
from vpn_node import Node, Peer
from vpn_tun import TunDevice

MAX_UDP = 2048   # socket read buffer. Anything longer than MAX_ESP is dropped before parsing.

# Output lines that mean an inbound datagram was refused. Outbound drops ("dropped tun packet")
# are local and are not counted. Cookie replies and accepted handshakes are not rejections.
_REJECT_PREFIXES = ("dropped packet from ", "dropped inner datagram from ")


def is_rejection(line: str) -> bool:
    return line.startswith(_REJECT_PREFIXES) or (line.startswith("handshake from ") and " rejected: " in line)


def say(msg: str, err: bool = False) -> None:
    """One console line with a local timestamp (open issue 31). There are no levels, no log file
    and no rotation: stdout or stderr is the log, and the operator redirects it."""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"{stamp} {msg}", file=sys.stderr if err else sys.stdout, flush=True)


def peer_file_digest(path: str) -> str:
    """SHA-256 of the peer file as read at startup, so an operator can check which file is in use (issue 29)."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class RejectCounter:
    """Passes every output line to `sink` and counts the inbound rejections. main() prints the
    count once at shutdown. This is a counter, not a logger: it keeps no lines and no addresses."""

    def __init__(self, sink: Callable[[str], None]):
        self.sink = sink
        self.count = 0

    def __call__(self, line: str) -> None:
        if is_rejection(line):
            self.count += 1
        self.sink(line)


def _safe_handle(node: Node, data: bytes, addr: tuple, now: float, out: Callable[[str], None]):
    """Node.handle, but an unexpected exception (a bug, not a protocol failure) only costs this
    datagram. The log gets the exception type, never its message, so no key or packet data leaks."""
    try:
        return node.handle(data, addr, now)
    except Exception as e:                                   # noqa: BLE001 - keep serving on any bug
        out(f"internal error on datagram from {addr}: {type(e).__name__}")
        return None


def _safe_poll(node: Node, now: float, out: Callable[[str], None]) -> list:
    """Node.poll with the same containment as _safe_handle."""
    try:
        return node.poll(now)
    except Exception as e:                                   # noqa: BLE001
        out(f"internal error in timers: {type(e).__name__}")
        return []


def serve(sock: socket.socket, node: Node, idle_timeout=None, echo=True, show_payload=False,
          out: Callable[[str], None] = print, tick: float = 1.0,
          on_tick: Optional[Callable[[float], None]] = None) -> None:
    """Serve tunnel peers on an already-bound UDP socket.

    Every datagram goes to Node.handle, which holds all protocol logic. This loop only moves
    bytes and prints. Timers run on each receive timeout. With idle_timeout None the loop
    returns at the first timeout, which is what the unit tests rely on. The CLI passes
    math.inf to run until stopped. Timers (node.poll) run on each receive timeout, and also
    once per tick while datagrams keep arriving, so they do not wait for an idle socket.
    """
    sock.settimeout(tick)
    last_rx = node.clock()
    next_timers = last_rx + tick
    while True:
        try:
            data, addr = sock.recvfrom(MAX_UDP)
        except socket.timeout:
            now = node.clock()
            if on_tick is not None:
                on_tick(now)           # e.g. peer file reload; runs in this thread, so Node stays single-threaded
            for pkt, dst in _safe_poll(node, now, out):
                sock.sendto(pkt, dst)
            next_timers = now + tick
            if idle_timeout is None or now - last_rx >= idle_timeout:
                return
            continue
        except ConnectionResetError:
            # Windows reports an ICMP port-unreachable for an earlier reply (the client closed its
            # port) on the next recvfrom. That is not a server fault, so keep serving.
            continue
        now = node.clock()
        if now >= next_timers:
            # Timers also run under steady traffic, where recvfrom never times out. One run per tick.
            if on_tick is not None:
                on_tick(now)
            for pkt, dst in _safe_poll(node, now, out):
                sock.sendto(pkt, dst)
            next_timers = now + tick
        last_rx = now
        act = _safe_handle(node, data, addr, now, out)
        if act is None:
            continue
        for pkt, dst in act.send:
            sock.sendto(pkt, dst)
        for line in act.events:
            out(line)
        if not act.inner:                 # None: not data. b"": keepalive, nothing to show.
            continue
        try:
            line = describe(act.inner, show_payload)
        except ESPError as e:
            out(f"dropped packet from {addr}: {e.reason}")
            continue
        out(f"<- decrypted {line}")
        if echo and act.peer is not None:
            # Demo behaviour: answer each datagram through the same session.
            try:
                src, dst, proto, payload = parse_ipv4(act.inner)
                sent = node.send(act.peer, build_ipv4(dst, src, proto, b"ack: " + payload), now)
                if sent is not None:
                    sock.sendto(sent[0], sent[1])
            except (ESPError, RekeyRequired) as e:
                out(f"reply not sent: {getattr(e, 'reason', 'rekey required')}")


def _pick_peer(node: Node, pkt: bytes) -> Optional[Peer]:
    """Cryptokey routing, outbound half: the peer whose allowed_ips contain the destination.
    With several peers, the first match wins. Peers with no current session are skipped."""
    if len(pkt) < 20:
        return None
    dst = ipaddress.IPv4Address(pkt[16:20])
    for peer in node.peers.values():
        if peer.current is not None and any(dst in net for net in peer.allowed_ips):
            return peer
    return None


def serve_tun(sock: socket.socket, node: Node, tun: TunDevice, idle_timeout=math.inf,
              out: Callable[[str], None] = print, tick: float = 1.0,
              on_tick: Optional[Callable[[float], None]] = None) -> None:
    """Move packets between the UDP socket and a TUN device, until idle_timeout.

    select() waits on both descriptors, so one thread drives Node, which is not thread safe.
    Decrypted inner packets are written to the device. Packets the host routes into the device
    go to _pick_peer and then Node.send. Keepalives (b"") are not written to the device.
    """
    tun_fd = tun.fileno()
    last_rx = node.clock()
    next_timers = last_rx + tick
    while True:
        readable, _, _ = select.select([sock, tun_fd], [], [], tick)
        now = node.clock()
        data = None
        if sock in readable:
            try:
                data, addr = sock.recvfrom(MAX_UDP)
            except ConnectionResetError:
                pass          # see serve(): an ICMP reset for an earlier reply, not a fault
        if data is not None:
            last_rx = now
            act = _safe_handle(node, data, addr, now, out)
            for pkt, dst in (act.send if act is not None else []):
                sock.sendto(pkt, dst)
            for line in (act.events if act is not None else []):
                out(line)
            if act is not None and act.inner:
                # Inbound check to match the outbound one below: only IPv4 goes into the device.
                if len(act.inner) >= 20 and act.inner[0] >> 4 == 4:
                    tun.write_packet(act.inner)
                else:
                    out(f"dropped inner datagram from {addr}: not IPv4")
        if tun_fd in readable:
            pkt = tun.read_packet()
            if len(pkt) >= 20 and pkt[0] >> 4 == 4:          # IPv4 only (see tun_linux.is_ipv4)
                peer = _pick_peer(node, pkt)
                if peer is None:
                    out("dropped tun packet: no peer with a session for this destination")
                else:
                    try:
                        sent = node.send(peer, pkt, now)
                    except (ESPError, RekeyRequired) as e:
                        out(f"dropped tun packet: {getattr(e, 'reason', 'rekey required')}")
                    else:
                        if sent is not None:
                            sock.sendto(sent[0], sent[1])
        if now >= next_timers:
            # Fixed schedule: at most one timer run per tick, however busy the device is.
            if on_tick is not None:
                on_tick(now)
            for pkt, dst in _safe_poll(node, now, out):
                sock.sendto(pkt, dst)
            next_timers = now + tick
        if now - last_rx >= idle_timeout:
            return


def main():
    ap = argparse.ArgumentParser(description="WireGuard-style tunnel server (loopback by default)")
    ap.add_argument("--bind", default="127.0.0.1", help="address to bind (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=4500)
    ap.add_argument("--key-file", help="file with this server's base64 private key (else IOESSA_VPN_PRIVATE_KEY)")
    ap.add_argument("--kem-key-file", help="file with this server's ML-KEM-768 seed (else IOESSA_VPN_KEM_KEY_FILE)")
    ap.add_argument("--peer-key-file", help="file with allowed peer keys, <X25519>:<ML-KEM> each "
                                            "(else IOESSA_VPN_PEER_PUBLIC_KEY)")
    ap.add_argument("--profile", choices=sorted(PROFILES), default="standard",
                    help="standard: session keys rotate every 120 s. strict: every 30 s, for less exposure "
                         "of any one session key. Handshake CPU cost is about the same")
    ap.add_argument("--use-psk", action="store_true", help="enable the optional pre-shared key (IOESSA_VPN_PSK)")
    ap.add_argument("--keepalive", type=float, default=KEEPALIVE_TIMEOUT, help="keepalive period in seconds, 0 disables")
    ap.add_argument("--load-threshold", type=int, default=DEFAULT_LOAD_THRESHOLD,
                    help="handshakes per second before cookie replies are required")
    ap.add_argument("--state-file", help=f"keep each peer's last handshake timestamp here, so replay protection "
                                         f"survives a restart (else {STATE_FILE_ENV}, else the default location "
                                         f"under your user profile). The file is tagged with a key derived from this "
                                         f"server's private key, and a file that fails the check stops the server")
    ap.add_argument("--max-key-age-days", type=int, default=int(os.environ.get("IOESSA_VPN_MAX_KEY_AGE_DAYS", "0")),
                    help="refuse to start with a static key older than this many days (0 = no limit, the default). "
                         "The key file needs its .created sidecar from vpn_keygen.py")
    ap.add_argument("--no-state-file", action="store_true",
                    help="keep replay state in memory only. A restart then reopens replay for captured handshakes")
    ap.add_argument("--idle-timeout", type=float, default=None, help="exit after this many idle seconds")
    ap.add_argument("--no-echo", action="store_true")
    ap.add_argument("--show-payload", action="store_true",
                    help="UNSAFE, demo only: prints decrypted plaintext to the console. Never use in production")
    ap.add_argument("--tun", choices=["queue", "linux", "windows"], default="queue",
                    help="queue: in-memory echo demo (default). linux: real TUN device (root, Linux only)")
    ap.add_argument("--tun-name", default="ioessa0", help="TUN device name (--tun linux)")
    ap.add_argument("--drop-to", metavar="USER", help="after TUN setup, switch to this user (--tun linux, run as root)")
    ap.add_argument("--tun-addr", default="10.8.0.1/24", help="TUN address in CIDR form (--tun linux)")
    ap.add_argument("--mtu", type=int, default=None,
                    help="TUN MTU (--tun linux). Default 1400: 1500 minus the 65-byte tunnel overhead, capped at MAX_INNER")
    ap.add_argument("--tun-route", action="append", default=None,
                    help="prefix to route into the tunnel (--tun linux, repeatable). Default 10.8.0.0/24")
    args = ap.parse_args()
    priv = load_static_private(args.key_file)
    try:
        check_key_age(args.key_file or os.environ.get(KEY_FILE_ENV), args.max_key_age_days)
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    psk = load_psk() if args.use_psk else b""
    if args.no_state_file:
        state_path = None
    else:
        state_path = args.state_file or os.environ.get(STATE_FILE_ENV) or default_state_path()
    try:
        store = None
        if state_path:
            os.makedirs(os.path.dirname(os.path.abspath(state_path)), exist_ok=True)
            store = TimestampStore(state_path, state_key(priv))
    except (StateFileError, OSError) as e:
        raise SystemExit(f"error: {e}")
    kem = load_kem_private(args.kem_key_file)
    node = Node(priv, psk, load_threshold=args.load_threshold, ts_store=store, kem_priv=kem,
                profile=PROFILES[args.profile])
    if store is None:
        say("WARNING: no --state-file (and no IOESSA_VPN_STATE_FILE). Replay protection for handshakes "
            "does NOT survive a restart. After a restart, a captured handshake is accepted again, "
            "which gives the replayer no keys and does not move the peer's endpoint. "
            "Use --state-file. See README.md.", err=True)
    else:
        say(f"replay state: {store.path} ({len(store)} peer timestamp(s) loaded)")
    tun_routes = args.tun_route or ["10.8.0.0/24"]

    def configure_peer(peer: Peer) -> None:
        """Policy for a peer, at startup and when the peer file adds one later."""
        peer.spd = [Policy(ipaddress.IPv4Network("0.0.0.0/0"), PROTECT)]   # echo replies go through the tunnel
        if args.tun in ("linux", "windows"):
            peer.allowed_ips = [ipaddress.IPv4Network(r, strict=True) for r in tun_routes]

    try:
        peer_entries = load_peer_entries(args.peer_key_file)
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    for pub, kem_pub, entry_psk in peer_entries:
        configure_peer(node.add_peer(pub, keepalive=args.keepalive or None, kem_pub=kem_pub,
                                     psk=entry_psk or None))
    if args.peer_key_file:
        say(f"peer file {args.peer_key_file}: {len(peer_entries)} peer(s), sha256 {peer_file_digest(args.peer_key_file)}")
    watcher = None
    if args.peer_key_file:
        # Revocation without a restart: the file is re-read every few seconds (peer_reload.py).
        watcher = PeerFileWatcher(node, args.peer_key_file, configure_peer, say,
                                  args.keepalive or None, check_disjoint=args.tun in ("linux", "windows"))
    if args.tun in ("linux", "windows"):
        # Imported here so the default queue path needs neither TUN backend.
        routes = args.tun_route or ["10.8.0.0/24"]
        if args.tun == "windows":
            if args.drop_to:
                ap.error("--drop-to applies only with --tun linux")
            from tun_windows import DEFAULT_MTU, WinTunError as TunError, WindowsTun as TunClass
            drop_privileges = None
        else:
            from tun_linux import DEFAULT_MTU, LinuxTun as TunClass, TunError, drop_privileges
        try:
            tun = TunClass(args.tun_name, args.tun_addr, DEFAULT_MTU if args.mtu is None else args.mtu, routes)
        except TunError as e:
            raise SystemExit(f"error: {e}")
        # Cryptokey routing: a peer may only send from, and receive packets for, the tunnel routes.
        for peer in node.peers.values():
            peer.allowed_ips = [ipaddress.IPv4Network(r, strict=True) for r in routes]
        # Every peer gets the same routes here, so with two or more peers a source address would
        # belong to all of them. Refuse that until per-peer routes can be configured.
        try:
            node.check_allowed_ips_disjoint()
        except ValueError as e:
            raise SystemExit(f"error: {e}. With --tun linux, the routes are shared by all peers, so use "
                             f"one peer per TUN server (per-peer routes are not supported yet)")
        counter = RejectCounter(say)
        with tun, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((args.bind, args.port))              # needs root below port 1024, so bind first
            if args.drop_to:
                try:
                    drop_privileges(args.drop_to)
                except TunError as e:
                    raise SystemExit(f"error: {e}")
                say(f"dropped privileges to {args.drop_to}")
            say(f"vpn_server listening on {args.bind}:{args.port}, TUN {tun.name} {args.tun_addr} "
                f"mtu {args.mtu or DEFAULT_MTU} ({len(node.peers)} peer(s))")
            try:
                serve_tun(sock, node, tun, math.inf if args.idle_timeout is None else args.idle_timeout,
                          out=counter, on_tick=watcher)
            except KeyboardInterrupt:
                say("stopped (Ctrl+C)")
            finally:
                say(f"rejected inbound datagrams this run: {counter.count + node.refusals_unlogged} "
                    f"({node.refusals_unlogged} not printed, log rate limit)")
        return
    if args.mtu is not None or args.tun_route or args.drop_to:
        ap.error("--mtu, --tun-route and --drop-to apply only with --tun linux")
    counter = RejectCounter(say)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.bind, args.port))
        say(f"vpn_server listening on {args.bind}:{args.port} ({len(node.peers)} peer(s))")
        try:
            serve(sock, node, math.inf if args.idle_timeout is None else args.idle_timeout,
                  not args.no_echo, args.show_payload, out=counter, on_tick=watcher)
        except KeyboardInterrupt:
            say("stopped (Ctrl+C)")
        finally:
            say(f"rejected inbound datagrams this run: {counter.count + node.refusals_unlogged} "
                f"({node.refusals_unlogged} not printed, log rate limit)")


if __name__ == "__main__":
    main()

