"""Linux TUN backend for vpn_tun.TunDevice. Standard library only.

What it does:
  * Opens /dev/net/tun and attaches a TUN device with the TUNSETIFF ioctl (IFF_TUN | IFF_NO_PI).
    IFF_NO_PI means every read and write is one raw IP packet with no 4-byte prefix info.
  * Configures the device through the `ip` command (iproute2), with argument lists and
    no shell. Every argument is validated before it is used.
  * Device lifetime: the device is non-persistent. It disappears when its file descriptor is
    closed, and so do the routes that point at it.

Needs root (or CAP_NET_ADMIN) to attach and configure. The module imports on any platform.
On Windows, LinuxTun raises TunError at construction, with no side effects.

Book references (Rosen, Linux Kernel Networking): Ch. 2 (netlink and iproute2: "ip tuntap
uses IOCTLs to add/remove a TUN/TAP device"), Appendix B, iproute2 section (the `ip tuntap` and
`ip route`/`ip addr` commands used here), Ch. 5 and 6 (routing table lookup; a route into the
tunnel is an ordinary FIB entry), and Ch. 10 (XFRM keeps SPD and SAD in the kernel; this
prototype keeps the equivalent in user space, which is why it needs no XFRM entries).
"""
import ipaddress
import os
import re
import shutil
import struct
import subprocess
import sys
from typing import Iterable, List, Optional, Sequence

from vpn_constants import DATA_HDR_LEN, MAX_INNER, TAG_LEN
from vpn_tun import TunDevice

try:
    import fcntl          # Linux and other Unix only; absent on Windows
except ImportError:
    fcntl = None

# ------------------------------------------------------------------ kernel constants
CLONE_DEVICE = "/dev/net/tun"
# _IOW('T', 202, int) from linux/if_tun.h. The ioctl number encodes direction, size, type and nr:
# dir (write) = 1 << 30, size = sizeof(int) = 4 << 16, type 'T' = 0x54 << 8, nr = 202 = 0xCA.
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001        # layer 3 device: packets are IP datagrams (IFF_TAP would be layer 2)
IFF_NO_PI = 0x1000      # no 4-byte packet-info header in front of each packet
IFNAMSIZ = 16           # kernel name buffer, including the trailing NUL
# struct ifreq as the TUN driver reads it: char ifr_name[16]; then a union (24 bytes on 64-bit)
# whose first member for this ioctl is short ifr_flags at offset 16. Total 40 bytes.
IFREQ = struct.Struct("16sH22x")
READ_BUF = 2048         # one read returns one packet; MTU is at most MAX_INNER (1400)

# ------------------------------------------------------------------ MTU math
IPV4_HDR = 20           # outer IPv4 header, no options (RFC 791)
UDP_HDR = 8             # outer UDP header
PAD_MAX = 3             # the trailer pads the inner datagram to a multiple of 4: 0 to 3 bytes
TRAILER_FIXED = 2       # pad length byte and next-header byte, from vpn_transport.seal_data
IPV4_MIN_MTU = 576      # RFC 791: every IPv4 host must accept at least 576 bytes
DEFAULT_LINK_MTU = 1500 # typical Ethernet; pass the real value for other links


def tunnel_overhead() -> int:
    """Worst-case bytes added to one inner datagram on the wire.

    Outer IPv4 (20) + UDP (8) + DATA header (16) + padding (0 to 3) + trailer (2) + Poly1305 tag (16).
    That is 65 bytes. Check with test_tun.py, which seals real packets and measures them.
    """
    return IPV4_HDR + UDP_HDR + DATA_HDR_LEN + PAD_MAX + TRAILER_FIXED + TAG_LEN


def max_tun_mtu(link_mtu: int = DEFAULT_LINK_MTU) -> int:
    """Largest safe TUN MTU. It must fit the link after the overhead, and it must not exceed
    MAX_INNER, because vpn_transport.seal_data refuses larger inner datagrams."""
    return min(MAX_INNER, link_mtu - tunnel_overhead())


DEFAULT_MTU = max_tun_mtu()     # 1400 on a 1500-byte link: 1465 on the wire, 35 bytes spare

# ------------------------------------------------------------------ validation
class TunError(RuntimeError):
    """A TUN operation failed. The message is safe to show to the user."""


_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,14}")   # IFNAMSIZ - 1 = 15 characters


def is_ipv4(pkt: bytes) -> bool:
    """True for a packet that looks like IPv4 (version nibble 4, at least a 20-byte header)."""
    return len(pkt) >= 20 and pkt[0] >> 4 == 4


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise TunError(f"invalid interface name {name!r}: use 1-15 letters, digits, '_' or '-', starting with a letter")
    return name


def validate_address(text: str) -> ipaddress.IPv4Interface:
    """Tunnel address in CIDR form, for example 10.8.0.1/24."""
    if not isinstance(text, str) or "/" not in text:
        raise TunError(f"tunnel address {text!r} must be in CIDR form, for example 10.8.0.1/24")
    try:
        iface = ipaddress.IPv4Interface(text)
    except ValueError:
        raise TunError(f"tunnel address {text!r} is not a valid IPv4 address with prefix") from None
    if not 8 <= iface.network.prefixlen <= 30:
        raise TunError(f"tunnel prefix /{iface.network.prefixlen} is outside /8 to /30")
    if iface.ip.is_unspecified or iface.ip.is_multicast or iface.ip.is_loopback or iface.ip == iface.network.broadcast_address:
        raise TunError(f"tunnel address {iface.ip} is not a usable unicast host address")
    return iface


def validate_mtu(mtu: int) -> int:
    # bool is a subclass of int, so reject it explicitly.
    if isinstance(mtu, bool) or not isinstance(mtu, int):
        raise TunError("MTU must be an integer")
    if not IPV4_MIN_MTU <= mtu <= MAX_INNER:
        raise TunError(f"MTU {mtu} is outside {IPV4_MIN_MTU} to {MAX_INNER} (MAX_INNER in vpn_constants.py)")
    return mtu


def validate_route(text: str) -> ipaddress.IPv4Network:
    """A route to send into the tunnel. The default route is refused: pointing 0.0.0.0/0 at the
    tunnel would send all traffic (including the tunnel's own UDP) into it and cut the host off."""
    if not isinstance(text, str) or "/" not in text:
        raise TunError(f"route {text!r} must be in CIDR form, for example 10.8.0.0/24")
    try:
        net = ipaddress.IPv4Network(text, strict=True)
    except ValueError:
        raise TunError(f"route {text!r} is not a valid IPv4 network (host bits set?)") from None
    if net.prefixlen == 0:
        raise TunError("refusing a default route into the tunnel (0.0.0.0/0); use a specific prefix")
    return net


# ------------------------------------------------------------------ commands
def build_ip_commands(name: str, address: str, mtu: int,
                      routes: Iterable[str] = ()) -> List[List[str]]:
    """The `ip` argument lists that configure the device. Pure function: nothing runs here.

    Order: address, MTU, then link up. The MTU is set before the link comes up, so the kernel
    never sends a packet larger than the tunnel can carry. Routes come last (Ch. 5: a route
    is a FIB entry that points at the device).
    """
    name = validate_name(name)
    iface = validate_address(address)
    mtu = validate_mtu(mtu)
    cmds = [
        ["addr", "add", str(iface), "dev", name],
        ["link", "set", "dev", name, "mtu", str(mtu)],
        ["link", "set", "dev", name, "up"],
    ]
    for r in routes:
        net = validate_route(r)
        # `ip addr add 10.8.0.1/24` already installs the connected route 10.8.0.0/24. Adding it
        # again fails with "File exists", so skip it.
        if net == iface.network:
            continue
        cmds.append(["route", "add", str(net), "dev", name])
    return cmds


def _run_ip(args: Sequence[str], timeout: float = 10.0) -> None:
    """Run `ip` with an argument list. shell=False, so no argument is ever parsed by a shell."""
    ip = shutil.which("ip")
    if ip is None:
        raise TunError("the 'ip' command was not found (install iproute2)")
    try:
        res = subprocess.run([ip, *args], shell=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise TunError(f"ip {' '.join(args)} failed: {e}") from None
    if res.returncode != 0:
        raise TunError(f"ip {' '.join(args)} failed: {res.stderr.strip() or 'exit ' + str(res.returncode)}")


# ------------------------------------------------------------------ the device
class LinuxTun(TunDevice):
    """A layer 3 TUN device. read_packet() returns one IPv4 datagram; write_packet() injects one."""

    def __init__(self, name: str = "ioessa0", address: Optional[str] = None,
                 mtu: int = DEFAULT_MTU, routes: Iterable[str] = ()):
        if sys.platform != "linux" or fcntl is None:
            raise TunError(f"LinuxTun needs Linux (/dev/net/tun and fcntl); this platform is {sys.platform!r}. "
                           "Use the default --tun queue here.")
        self.name = validate_name(name)
        self._fd: Optional[int] = None
        try:
            fd = os.open(CLONE_DEVICE, os.O_RDWR)
        except FileNotFoundError:
            raise TunError(f"{CLONE_DEVICE} does not exist (load the module with: sudo modprobe tun)") from None
        except PermissionError:
            raise TunError(f"permission denied opening {CLONE_DEVICE}: run as root or with CAP_NET_ADMIN") from None
        try:
            # The kernel writes the final name back into the buffer, so read it from the reply.
            reply = fcntl.ioctl(fd, TUNSETIFF, IFREQ.pack(name.encode("ascii"), IFF_TUN | IFF_NO_PI))
        except OSError as e:
            os.close(fd)
            raise TunError(f"TUNSETIFF for {name} failed: {e} (is the name already in use?)") from None
        self.name = reply[:IFNAMSIZ].rstrip(b"\0").decode("ascii")
        self._fd = fd
        if address is not None:
            try:
                self.configure(address, mtu, routes)
            except TunError:
                self.close()        # closing the fd destroys the non-persistent device
                raise

    def configure(self, address: str, mtu: int, routes: Iterable[str] = ()) -> None:
        """Set the address, MTU and link state, then add routes. Validates everything first."""
        cmds = build_ip_commands(self.name, address, mtu, routes)   # raises before anything runs
        for args in cmds:
            _run_ip(args)

    def fileno(self) -> int:
        """File descriptor, so a caller can select() on it alongside sockets."""
        if self._fd is None:
            raise TunError("TUN device is closed")
        return self._fd

    def read_packet(self) -> bytes:
        """One raw packet from the kernel. The caller drops anything that is not IPv4 (see
        is_ipv4): the tunnel carries IPv4 only, and the kernel may emit IPv6 frames on its own.
        This is a single read, so a select() loop never blocks on a frame it will drop."""
        return os.read(self.fileno(), READ_BUF)

    def write_packet(self, pkt: bytes) -> None:
        """Inject one IPv4 packet into the host's stack."""
        os.write(self.fileno(), pkt)

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> "LinuxTun":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def drop_privileges(user: str) -> None:
    """Switch the process to `user` for the rest of its life. Call it after the TUN device, its
    address and routes exist, and after the UDP socket is bound. The open TUN descriptor keeps
    working, and closing it needs no privilege. The change is irreversible, and that is checked:
    if the process could become root again, this raises rather than continue."""
    if os.name != "posix" or not hasattr(os, "setuid"):
        raise TunError("privilege drop needs a POSIX system")
    if os.geteuid() != 0:
        raise TunError("--drop-to needs the process to start as root, so that the TUN setup can run")
    import pwd
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        raise TunError(f"no such user: {user}") from None
    if entry.pw_uid == 0:
        raise TunError("refusing to drop to root")
    os.setgroups([])                    # supplementary groups go first, while still root
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)
    if os.getuid() != entry.pw_uid or os.geteuid() != entry.pw_uid:
        raise TunError("privilege drop did not take effect")
    try:
        os.setuid(0)
    except PermissionError:
        return                          # cannot become root again, as required
    raise TunError("privilege drop could be undone: refusing to continue")