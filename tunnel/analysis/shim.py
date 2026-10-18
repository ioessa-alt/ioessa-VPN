"""Test-only UDP shim: adds loss and latency to a real loopback socket, without admin rights.

LossyUDP wraps a UDP socket. In each direction it drops a datagram with probability `loss`
and adds `latency` seconds of delay (outbound sends are delayed on a timer thread, inbound
datagrams are delayed before recvfrom returns). Drops use the seeded RNG passed in, so a run
can be repeated. Everything else is forwarded to the socket. It is not a network emulator:
it does not model bandwidth, jitter, reordering or queues.
"""
import socket
import threading
import time
from typing import Callable, Optional, Tuple


class LossyUDP:
    def __init__(self, sock: socket.socket, rng, loss: float = 0.0, latency: float = 0.0,
                 on_send: Optional[Callable[[bytes, tuple], None]] = None):
        if not 0.0 <= loss < 1.0:
            raise ValueError("loss must be in [0, 1)")
        self._sock = sock
        self._rng = rng
        self.loss = loss
        self.latency = latency
        self._on_send = on_send
        self._timeout = sock.gettimeout()
        self.sent = 0
        self.dropped_out = 0
        self.dropped_in = 0
        self.received = 0

    # -- socket API used by the tunnel scripts
    def sendto(self, data, addr: Tuple[str, int]):
        self.sent += 1
        if self._on_send is not None:
            self._on_send(bytes(data), addr)
        if self._rng.random() < self.loss:
            self.dropped_out += 1
            return len(data)
        if self.latency > 0:
            threading.Timer(self.latency, self._send_later, args=(bytes(data), addr)).start()
            return len(data)
        return self._sock.sendto(data, addr)

    def _send_later(self, data: bytes, addr) -> None:
        try:
            self._sock.sendto(data, addr)
        except OSError:
            pass                            # socket closed before the delay ended

    def recvfrom(self, bufsize: int):
        deadline = None if self._timeout is None else time.monotonic() + self._timeout
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("timed out")
                self._sock.settimeout(remaining)
            try:
                data, addr = self._sock.recvfrom(bufsize)
            finally:
                self._sock.settimeout(self._timeout)
            if self._rng.random() < self.loss:
                self.dropped_in += 1
                continue
            if self.latency > 0:
                time.sleep(self.latency)
            self.received += 1
            return data, addr

    def settimeout(self, value) -> None:
        self._timeout = value
        self._sock.settimeout(value)

    def gettimeout(self):
        return self._timeout

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> "LossyUDP":
        return self

    def __exit__(self, *exc) -> None:
        self._sock.close()

    def __getattr__(self, name):
        return getattr(self._sock, name)
