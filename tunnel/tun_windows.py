"""Windows TUN backend on Wintun (open issue 13). Layer 3, like tun_linux.py.

Wintun is WireGuard's driver. The DLL is loaded with ctypes. A reader thread takes packets from the
ring and hands them to a queue. A socket pair carries one byte per packet, so serve_tun() can select()
on fileno() next to the UDP socket. Only Windows can load the DLL. The rest of the module imports anywhere.

Creating the adapter needs administrator rights. Set IOESSA_WINTUN_DLL to the DLL path, or install it at
%LOCALAPPDATA%\\ioessa-vpn\\wintun\\wintun.dll (the default). The download and its signature check are in
the README.
"""
import ctypes
import os
import queue
import socket
import subprocess
import sys
import threading
from ctypes import wintypes
from typing import Callable, Iterable, List, Optional, Sequence

from vpn_tun import TunDevice

ADAPTER_NAME = "ioessa"
RING_CAPACITY = 0x400000            # bytes; Wintun needs a power of two between 128 KiB and 64 MiB
DEFAULT_MTU = 1400                  # the same value as tun_linux (1500 minus the tunnel overhead)
MAX_PACKET = 0xFFFF
WAIT_MS = 100


class WinTunError(Exception):
    """Wintun or netsh could not set the adapter up."""


def default_dll_path() -> str:
    env = os.environ.get("IOESSA_WINTUN_DLL")
    if env:
        return env
    return os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "ioessa-vpn", "wintun", "wintun.dll")


def load_wintun(path: Optional[str] = None):
    """Load wintun.dll and set the function signatures. Windows only."""
    if sys.platform != "win32":
        raise WinTunError("Wintun is Windows only")
    dll_path = path or default_dll_path()
    if not os.path.exists(dll_path):
        raise WinTunError(f"wintun.dll not found at {dll_path}. Download it from wintun.net and set IOESSA_WINTUN_DLL")
    lib = ctypes.WinDLL(dll_path)
    P = ctypes.c_void_p
    sigs = {
        "WintunCreateAdapter": (P, [wintypes.LPCWSTR, wintypes.LPCWSTR, P]),
        "WintunCloseAdapter": (None, [P]),
        "WintunStartSession": (P, [P, wintypes.DWORD]),
        "WintunEndSession": (None, [P]),
        "WintunGetReadWaitEvent": (wintypes.HANDLE, [P]),
        "WintunReceivePacket": (ctypes.POINTER(ctypes.c_ubyte), [P, ctypes.POINTER(wintypes.DWORD)]),
        "WintunReleaseReceivePacket": (None, [P, ctypes.POINTER(ctypes.c_ubyte)]),
        "WintunAllocateSendPacket": (ctypes.POINTER(ctypes.c_ubyte), [P, wintypes.DWORD]),
        "WintunSendPacket": (None, [P, ctypes.POINTER(ctypes.c_ubyte)]),
    }
    for name, (restype, argtypes) in sigs.items():
        fn = getattr(lib, name)
        fn.restype = restype
        fn.argtypes = argtypes
    return lib


def _kernel32_wait(handle, timeout_ms: int) -> None:
    """Wait on a Windows event handle for up to timeout_ms. Windows only."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitForSingleObject(handle, timeout_ms)


def build_netsh_commands(name: str, address: str, mtu: int, routes: Iterable[str]) -> List[List[str]]:
    """The netsh commands that give the adapter its address, MTU and routes. Pure: nothing is run here.
    `address` is CIDR (10.8.0.1/24)."""
    import ipaddress
    iface = ipaddress.IPv4Interface(address)
    cmds = [
        ["netsh", "interface", "ipv4", "set", "address", f"name={name}", "source=static",
         f"address={iface.ip}", f"mask={iface.netmask}"],
        ["netsh", "interface", "ipv4", "set", "subinterface", name, f"mtu={mtu}", "store=active"],
    ]
    for prefix in routes:
        net = ipaddress.IPv4Network(prefix, strict=True)
        cmds.append(["netsh", "interface", "ipv4", "add", "route", str(net), name, "store=active"])
    return cmds


class WindowsTun(TunDevice):
    """A Wintun adapter. read_packet() returns one raw IPv4 datagram. write_packet() injects one."""

    def __init__(self, name: str = ADAPTER_NAME, address: Optional[str] = None, mtu: int = DEFAULT_MTU,
                 routes: Sequence[str] = (), lib=None, run: Callable = subprocess.run,
                 wait: Optional[Callable] = None):
        self.name = name
        self._lib = lib if lib is not None else load_wintun()
        self._wait = wait if wait is not None else _kernel32_wait
        self._adapter = self._lib.WintunCreateAdapter(name, "ioessa", None)
        if not self._adapter:
            raise WinTunError(f"could not create the Wintun adapter {name} (run as administrator?)")
        self._session = self._lib.WintunStartSession(self._adapter, RING_CAPACITY)
        if not self._session:
            self._lib.WintunCloseAdapter(self._adapter)
            raise WinTunError("could not start a Wintun session")
        self._wait_event = self._lib.WintunGetReadWaitEvent(self._session)
        self._queue: "queue.Queue[bytes]" = queue.Queue()
        self._wake_r, self._wake_w = socket.socketpair()
        self._stop = threading.Event()
        self._closed = False
        self._reader = threading.Thread(target=self._read_loop, name="wintun-reader", daemon=True)
        self._reader.start()
        if address is not None:
            for cmd in build_netsh_commands(name, address, mtu, routes):
                try:
                    run(cmd, check=True, capture_output=True, text=True)
                except (OSError, subprocess.CalledProcessError) as e:
                    self.close()
                    raise WinTunError(f"netsh failed: {' '.join(cmd[:4])}: {getattr(e, 'stderr', e)}") from None

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            self._wait(self._wait_event, WAIT_MS)
            while not self._stop.is_set():
                size = wintypes.DWORD(0)
                ptr = self._lib.WintunReceivePacket(self._session, ctypes.byref(size))
                if not ptr:
                    break
                data = ctypes.string_at(ptr, size.value)
                self._lib.WintunReleaseReceivePacket(self._session, ptr)
                self._queue.put(data)
                try:
                    self._wake_w.send(b"\0")          # one byte per packet, so select() sees each one
                except OSError:
                    return

    def fileno(self) -> int:
        """Read side of the wake-up socket pair. select() on it means at least one packet is queued."""
        return self._wake_r.fileno()

    def read_packet(self) -> bytes:
        self._wake_r.recv(1)
        return self._queue.get()

    def write_packet(self, pkt: bytes) -> None:
        if len(pkt) > MAX_PACKET:
            raise WinTunError("packet too large for Wintun")
        ptr = self._lib.WintunAllocateSendPacket(self._session, len(pkt))
        if not ptr:
            raise WinTunError("Wintun send ring is full; packet dropped")
        ctypes.memmove(ptr, pkt, len(pkt))
        self._lib.WintunSendPacket(self._session, ptr)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        self._reader.join(timeout=2.0)
        self._lib.WintunEndSession(self._session)
        self._lib.WintunCloseAdapter(self._adapter)
        self._wake_r.close()
        self._wake_w.close()

    def __enter__(self) -> "WindowsTun":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


if __name__ == "__main__":
    # Real check, from an elevated shell: create an adapter, start a session, and close it.
    if "--selftest" in sys.argv:
        try:
            with WindowsTun(name="ioessa-selftest") as tun:
                print(f"adapter {tun.name} created and session started; closing")
        except WinTunError as e:
            raise SystemExit(f"selftest failed: {e}")
        print("selftest ok")
    else:
        print("usage: python tun_windows.py --selftest   (run from an elevated shell)")
