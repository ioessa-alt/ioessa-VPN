"""VPN tunnel client (UDP transport), WireGuard-style initiator. See vpn_node.py.

Usage (PowerShell; keys from env vars or files, never from source):
    $env:IOESSA_VPN_PRIVATE_KEY = "<this client's base64 private key>"
    $env:IOESSA_VPN_PEER_PUBLIC_KEY = "<server public key, base64>"
    python vpn_client.py --server 127.0.0.1 --port 4500 --protect 10.8.0.0/24 --packets 3

Without a real TUN adapter, the "inner datagrams" are generated here and the replies are
printed. The SPD decides per destination whether a datagram goes through the tunnel
(PROTECT) or is left alone (BYPASS). --roam-after N moves this client to a new UDP port
before packet N, to show roaming.

Real TUN (Linux, root): --tun linux creates a TUN device with --tun-addr (default 10.8.0.2/24).
The route for --protect (or --tun-route) points at the device, so packets the host sends to
that prefix are tunnelled. Replies are written back into the host's stack. See README.md.
"""
import argparse
import ipaddress
import math
import os
import select
import socket
import time
from typing import Callable

from vpn_constants import KEEPALIVE_TIMEOUT, KEY_FILE_ENV, MAX_ESP, PROFILES
from vpn_errors import ESPError, RekeyRequired
from vpn_keyfiles import check_key_age, load_kem_private, load_peer_entries, load_psk, load_static_private
from vpn_ip import build_ipv4, BYPASS, describe, Policy, PROTECT
from vpn_node import Node, Peer
from vpn_tun import TunDevice

MAX_UDP = 2048


def _recv_from(sock: socket.socket, server: tuple, timeout: float, want=None) -> bytes:
    """Wait for a datagram from the server only, within an overall deadline.

    Other sources, oversize datagrams and datagrams that fail `want` are ignored. The
    deadline stops a flood from other addresses from holding the client here forever.
    """
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("timed out waiting for the server")
        sock.settimeout(remaining)
        try:
            data, addr = sock.recvfrom(MAX_UDP)
        except ConnectionResetError:
            # Windows reports an ICMP port-unreachable from an earlier send on the next recv.
            # The server is gone or not listening. Keep waiting until the deadline expires.
            continue
        if addr == server and len(data) <= MAX_ESP and (want is None or want(data)):
            return data


def _send_all(sock: socket.socket, packets) -> None:
    for pkt, dst in packets:
        sock.sendto(pkt, dst)


def handshake_any(sock: socket.socket, node: Node, peers: list, server: tuple, timeout: float,
                  out: Callable[[str], None] = print) -> Peer:
    """Run handshakes with each candidate server key at once, until one of them completes.

    Each candidate is a Peer with the same endpoint and its own server key. The INIT for every key
    goes out in the first round. Only the server that holds the matching private key answers
    (mac1 is checked silently), so at most one candidate completes. The other candidates are
    removed from the node. Returns the peer that now has a current session.
    """
    old = {p.pub: p.current for p in peers}
    deadline = time.monotonic() + timeout
    for p in peers:
        _send_all(sock, node.initiate(p))
    while True:
        for p in peers:
            if p.current is not None and p.current is not old[p.pub]:
                for other in peers:
                    if other is not p:
                        node.remove_peer(other.pub)
                return p
        now = time.monotonic()
        if now >= deadline:
            raise socket.timeout("timed out waiting for the server")
        _send_all(sock, node.poll(now))    # retransmission and cookie handling for every candidate
        try:
            data = _recv_from(sock, server, min(0.2, deadline - now))
        except socket.timeout:
            continue
        act = node.handle(data, server, time.monotonic())
        _send_all(sock, act.send)          # includes the confirmation keepalive (V-C)
        for line in act.events:
            out(line)


def handshake(sock: socket.socket, node: Node, peer: Peer, server: tuple, timeout: float,
              out: Callable[[str], None] = print) -> None:
    """Run the handshake until a new current session exists (V-D), for one peer.

    Retransmission, cookie replies and rekey timers are all driven by node.poll(). This loop
    only moves the bytes.
    """
    handshake_any(sock, node, [peer], server, timeout, out)


def send_inner(sock: socket.socket, node: Node, peer: Peer, server: tuple, inner: bytes,
               timeout: float, out: Callable[[str], None] = print) -> None:
    """Send one inner datagram. On RekeyRequired, run the handshake again and send it once more."""
    try:
        sent = node.send(peer, inner)
    except RekeyRequired:
        out("sequence limit reached, re-keying")
        handshake(sock, node, peer, server, timeout, out)
        sent = node.send(peer, inner)
    if sent is None:
        out(f"bypass (SPD): {describe(inner)}")
    else:
        sock.sendto(sent[0], sent[1])
        out(f"-> encrypted {describe(inner)}")


def run_tun(sock: socket.socket, node: Node, peer: Peer, server: tuple, tun: TunDevice,
            timeout: float, idle_timeout=math.inf, out: Callable[[str], None] = print,
            tick: float = 1.0) -> None:
    """Tunnel TUN traffic until idle_timeout. Same select() design as vpn_server.serve_tun.

    IPv4 packets from the device go through send_inner (SPD, then encryption, then a re-key if
    needed). Datagrams from the server are decrypted and written to the device. Re-keying runs
    the blocking handshake() from this thread, so the device queues packets while it runs.
    """
    tun_fd = tun.fileno()
    last_rx = time.monotonic()
    while True:
        readable, _, _ = select.select([sock, tun_fd], [], [], tick)
        now = time.monotonic()
        if sock in readable:
            try:
                data, addr = sock.recvfrom(MAX_UDP)
            except ConnectionResetError:
                # ICMP port-unreachable surfaces here on Windows. Count it as silence, not a crash.
                out("server unreachable (ICMP port unreachable); retrying")
                data, addr = b"", None
            if addr == server and len(data) <= MAX_ESP:
                last_rx = now
                act = node.handle(data, server, now)
                _send_all(sock, act.send)
                for line in act.events:
                    out(line)
                if act.inner:
                    # Inbound check to match the outbound one below: only IPv4 goes into the device.
                    if len(act.inner) >= 20 and act.inner[0] >> 4 == 4:
                        tun.write_packet(act.inner)
                    else:
                        out("dropped inner datagram from server: not IPv4")
        if tun_fd in readable:
            pkt = tun.read_packet()
            if len(pkt) >= 20 and pkt[0] >> 4 == 4:          # IPv4 only (see tun_linux.is_ipv4)
                try:
                    send_inner(sock, node, peer, server, pkt, timeout, out)
                except ESPError as e:
                    out(f"dropped tun packet: {e.reason}")
        _send_all(sock, node.poll(now))
        if now - last_rx >= idle_timeout:
            return


def _bind(host: str = "127.0.0.1") -> socket.socket:
    # Loopback with an ephemeral port by default, so the client is not reachable from the network.
    # --local-bind changes the address, for example to reach a server across a veth pair.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, 0))
    return sock


def main():
    ap = argparse.ArgumentParser(description="WireGuard-style tunnel client")
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4500)
    ap.add_argument("--protect", default="10.8.0.0/24", help="inner destinations sent through the tunnel")
    ap.add_argument("--packets", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--key-file", help="file with this client's base64 private key (else IOESSA_VPN_PRIVATE_KEY)")
    ap.add_argument("--kem-key-file", help="file with this client's ML-KEM-768 seed (else IOESSA_VPN_KEM_KEY_FILE)")
    ap.add_argument("--peer-key-file", help="file with the server's entry, <X25519>:<ML-KEM> "
                                            "(else IOESSA_VPN_PEER_PUBLIC_KEY)")
    ap.add_argument("--profile", choices=sorted(PROFILES), default="standard",
                    help="standard: session keys rotate every 120 s. strict: every 30 s, for less exposure "
                         "of any one session key. Handshake CPU cost is about the same")
    ap.add_argument("--use-psk", action="store_true", help="enable the optional pre-shared key (IOESSA_VPN_PSK)")
    ap.add_argument("--keepalive", type=float, default=KEEPALIVE_TIMEOUT, help="keepalive period in seconds, 0 disables")
    ap.add_argument("--roam-after", type=int, default=None,
                    help="change this client's UDP port before packet N (roaming demo)")
    ap.add_argument("--show-payload", action="store_true",
                    help="UNSAFE, demo only: prints decrypted plaintext to the console. Never use in production")
    ap.add_argument("--local-bind", default="127.0.0.1",
                    help="local address for the UDP socket (default 127.0.0.1; use a veth address for netns tests)")
    ap.add_argument("--tun", choices=["queue", "linux"], default="queue",
                    help="queue: generated demo packets (default). linux: real TUN device (root, Linux only)")
    ap.add_argument("--tun-name", default="ioessa0", help="TUN device name (--tun linux)")
    ap.add_argument("--tun-addr", default="10.8.0.2/24", help="TUN address in CIDR form (--tun linux)")
    ap.add_argument("--mtu", type=int, default=None,
                    help="TUN MTU (--tun linux). Default 1400: 1500 minus the 65-byte tunnel overhead, capped at MAX_INNER")
    ap.add_argument("--tun-route", action="append", default=None,
                    help="prefix to route into the tunnel (--tun linux, repeatable). Default: the --protect prefix")
    ap.add_argument("--drop-to", metavar="USER", help="after TUN setup, switch to this user (--tun linux, run as root)")
    ap.add_argument("--max-key-age-days", type=int, default=int(os.environ.get("IOESSA_VPN_MAX_KEY_AGE_DAYS", "0")),
                    help="refuse to start with a static key older than this many days (0 = no limit, the default). "
                         "The key file needs its .created sidecar from vpn_keygen.py")
    args = ap.parse_args()

    priv = load_static_private(args.key_file)
    try:
        check_key_age(args.key_file or os.environ.get(KEY_FILE_ENV), args.max_key_age_days)
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    # One candidate peer per configured server key (duplicates removed). See handshake_any.
    server_entries = list(dict.fromkeys(load_peer_entries(args.peer_key_file)))
    psk = load_psk() if args.use_psk else b""
    server = (args.server, args.port)
    kem = load_kem_private(args.kem_key_file)
    node = Node(priv, psk, kem_priv=kem, profile=PROFILES[args.profile])
    candidates = [node.add_peer(pub, endpoint=server, keepalive=args.keepalive or None, kem_pub=kem_pub,
                                psk=entry_psk or None)
                  for pub, kem_pub, entry_psk in server_entries]
    for peer in candidates:
        peer.spd = [Policy(ipaddress.IPv4Network(args.protect), PROTECT),
                    Policy(ipaddress.IPv4Network("0.0.0.0/0"), BYPASS)]
    if args.tun == "queue" and (args.mtu is not None or args.tun_route or args.drop_to):
        ap.error("--mtu, --tun-route and --drop-to apply only with --tun linux")

    tun = None
    if args.tun == "linux":
        # Created before the handshake, so bad arguments and a missing Linux fail at once.
        # Imported here so the default queue path does not need tun_linux at all.
        from tun_linux import DEFAULT_MTU, LinuxTun, TunError
        routes = args.tun_route or [args.protect]
        try:
            tun = LinuxTun(args.tun_name, args.tun_addr, DEFAULT_MTU if args.mtu is None else args.mtu, routes)
        except TunError as e:
            raise SystemExit(f"error: {e}")
        # Cryptokey routing: replies may only come from the tunnel routes.
        for peer in candidates:
            peer.allowed_ips = [ipaddress.IPv4Network(r, strict=True) for r in routes]
    sock = _bind(args.local_bind)
    if args.drop_to:
        # The TUN device, its address and routes exist, and the socket is bound, so root is no longer needed.
        from tun_linux import TunError, drop_privileges
        try:
            drop_privileges(args.drop_to)
        except TunError as e:
            sock.close()
            raise SystemExit(f"error: {e}")
        print(f"dropped privileges to {args.drop_to}", flush=True)
    try:
        try:
            peer = handshake_any(sock, node, candidates, server, args.timeout)
        except socket.timeout:
            print("error: no handshake response from the server (check the port and both public keys)", flush=True)
            raise SystemExit(1)
        sess = peer.current
        print(f"tunnel up: local index {sess.local_index:#010x}, remote index {sess.remote_index:#010x}",
              flush=True)
        if tun is not None:
            print(f"TUN {tun.name} {args.tun_addr} up; Ctrl+C to stop", flush=True)
            try:
                run_tun(sock, node, peer, server, tun, args.timeout, out=lambda s: print(s, flush=True))
            except KeyboardInterrupt:
                print("stopped", flush=True)
            return
        for i in range(args.packets):
            if args.roam_after is not None and i == args.roam_after:
                old_port = sock.getsockname()[1]
                sock.close()
                sock = _bind(args.local_bind)
                print(f"roaming: client port {old_port} -> {sock.getsockname()[1]}", flush=True)
            inner = build_ipv4("10.8.0.2", "10.8.0.1", 253, f"hello #{i} over ESP".encode())
            send_inner(sock, node, peer, server, inner, args.timeout)
            try:
                reply = _recv_from(sock, server, args.timeout)
            except socket.timeout:
                print("timed out waiting for reply", flush=True)
                continue
            act = node.handle(reply, server, time.monotonic())
            _send_all(sock, act.send)
            for line in act.events:
                print(line, flush=True)
            if act.inner:
                print(f"<- decrypted {describe(act.inner, args.show_payload)}", flush=True)
        # One datagram outside the protected prefix: the SPD bypasses it.
        send_inner(sock, node, peer, server, build_ipv4("10.8.0.2", "8.8.8.8", 253, b"not protected"),
                   args.timeout)
    finally:
        sock.close()
        if tun is not None:
            tun.close()


if __name__ == "__main__":
    main()

