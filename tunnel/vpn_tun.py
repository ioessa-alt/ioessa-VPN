"""TUN device interface and an in-memory queue implementation."""
import abc
import queue


# ------------------------------------------------------------------ TUN interface
class TunDevice(abc.ABC):
    """Where inner IP datagrams come from and go to. The core never needs a real adapter."""

    @abc.abstractmethod
    def read_packet(self) -> bytes: ...

    @abc.abstractmethod
    def write_packet(self, pkt: bytes) -> None: ...

    def close(self) -> None:
        pass


class QueueTun(TunDevice):
    """In-memory stand-in for a TUN device, used by tests and the loopback demo."""

    def __init__(self):
        self.rx = queue.Queue()   # packets "read from the OS" (to be sent into the tunnel)
        self.tx = queue.Queue()   # packets "written to the OS" (decrypted from the tunnel)

    def read_packet(self) -> bytes:
        return self.rx.get()

    def write_packet(self, pkt: bytes) -> None:
        self.tx.put(pkt)
