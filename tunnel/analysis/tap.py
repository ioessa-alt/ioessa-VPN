"""Opt-in capture hook for the tunnel endpoints. Off unless asked for. Writes two pcap files:

  outer.pcap  the UDP datagrams as they cross the socket, i.e. the ciphertext on the wire
              (wrapped in IPv4/UDP headers so the file is LINKTYPE_RAW)
  inner.pcap  the IPv4 packets as the TUN side sees them, in plaintext: received packets after
              decryption, and sent packets before encryption

The hook changes no existing file. It wraps the socket and the Node at the point where the
scripts use them:

  * TappedSocket proxies sendto/recvfrom and records each datagram. select() still works,
    because fileno() is forwarded and the proxy object is the one passed to select.
  * tap_node wraps Node.handle and Node.send on one instance. Packets are recorded only when
    they really are inner packets: keepalives (b"") and BYPASS packets are not recorded.

Two ways to turn it on, both opt-in:
  python analysis/capture_run.py --capture-dir DIR server [vpn_server options]
  python analysis/capture_run.py --capture-dir DIR client [vpn_client options]
  (or set IOESSA_VPN_CAPTURE_DIR=DIR and run capture_run.py without the flag)
Without either, capture_run.py just calls the script's main() unchanged.

Each endpoint writes its own pair of files, so run the server and client with different
directories. Server and client captures of the same run then show the same packets from
each side. Captures hold ciphertext and inner plaintext, never key material.
"""
import os
import socket as _socket
import threading
import time
from typing import Callable, Tuple

from pcap import PcapWriter, build_ipv4_udp

ENV_CAPTURE_DIR = "IOESSA_VPN_CAPTURE_DIR"
OUTER_NAME = "outer.pcap"
INNER_NAME = "inner.pcap"


class CaptureSink:
    """The two pcap writers for one endpoint, plus the lock that makes them thread-safe."""

    def __init__(self, directory: str):
        os.makedirs(directory, exist_ok=True)
        self.directory = directory
        self.outer = PcapWriter(os.path.join(directory, OUTER_NAME))
        self.inner = PcapWriter(os.path.join(directory, INNER_NAME))
        self._lock = threading.Lock()
        self._ident = 0

    def outer_datagram(self, payload: bytes, src: Tuple[str, int], dst: Tuple[str, int]) -> None:
        with self._lock:
            self._ident = (self._ident + 1) & 0xFFFF
            pkt = build_ipv4_udp(src[0], src[1], dst[0], dst[1], bytes(payload), self._ident)
        self.outer.write(pkt, time.time())

    def inner_packet(self, pkt: bytes) -> None:
        if pkt:
            self.inner.write(bytes(pkt), time.time())

    def close(self) -> None:
        self.outer.close()
        self.inner.close()


class TappedSocket:
    """Proxy for a UDP socket that records each datagram. Everything else goes to the socket."""

    def __init__(self, sock: _socket.socket, sink: CaptureSink):
        self._sock = sock
        self._sink = sink

    def _local(self) -> Tuple[str, int]:
        return self._sock.getsockname()[:2]

    def sendto(self, data, *args):
        n = self._sock.sendto(data, *args)
        self._sink.outer_datagram(bytes(data), self._local(), args[-1])
        return n

    def recvfrom(self, bufsize, *args):
        data, addr = self._sock.recvfrom(bufsize, *args)
        self._sink.outer_datagram(bytes(data), addr[:2], self._local())
        return data, addr

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> "TappedSocket":
        return self

    def __exit__(self, *exc) -> None:
        self._sock.close()

    def __getattr__(self, name):
        return getattr(self._sock, name)


class _SocketModule:
    """Stands in for the `socket` module inside one script. Only socket.socket is replaced."""

    def __init__(self, sink: CaptureSink):
        self._sink = sink

    def socket(self, *args, **kwargs) -> TappedSocket:
        return TappedSocket(_socket.socket(*args, **kwargs), self._sink)

    def __getattr__(self, name):
        return getattr(_socket, name)


def tap_node(node, sink: CaptureSink):
    """Record inner packets on one Node instance. Returns the same node."""
    real_handle, real_send = node.handle, node.send

    def handle(data, src, now=None):
        act = real_handle(data, src, now)
        if act.inner:                       # decrypted inbound packet; b"" is a keepalive
            sink.inner_packet(act.inner)
        return act

    def send(peer, inner, now=None):
        out = real_send(peer, inner, now)
        if out is not None:                 # encrypted outbound packet (not BYPASS)
            sink.inner_packet(inner)
        return out

    node.handle = handle
    node.send = send
    return node


def install(module, sink: CaptureSink) -> None:
    """Point one script module at the tap: its `socket` name and its `Node` name.
    Used by capture_run.py. vpn_server and vpn_client both do `from vpn_node import Node`
    and `import socket`, so these two names are all they use."""
    module.socket = _SocketModule(sink)
    make_node: Callable = module.Node

    def tapped_node(*args, **kwargs):
        return tap_node(make_node(*args, **kwargs), sink)

    module.Node = tapped_node
