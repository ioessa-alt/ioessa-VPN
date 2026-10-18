"""Runtime peer revocation. The server re-reads its peer file while it runs, so a key removed from
the file stops working without a restart.

PeerFileWatcher is called once per timer tick from the serving thread (Node is not thread safe).
It reads the file every `interval` seconds, and applies it only when its contents have changed:

  * a peer no longer in the file is removed with Node.remove_peer, which drops its sessions and any
    handshake in progress, so its packets are refused from that tick on;
  * a peer whose ML-KEM key changed is removed and added again with the new key;
  * a new peer is added and passed to `configure`, which sets its policy (SPD, allowed_ips).

A file that cannot be read or does not parse, or that is empty, is refused. The current peers stay,
so a bad edit cannot silently lock everyone out. Removing every peer therefore needs a restart.
"""
from typing import Callable, Iterable, Optional, Tuple

from vpn_keyfiles import load_peer_entries
from vpn_node import Node, Peer


class PeerFileWatcher:
    def __init__(self, node: Node, path: str, configure: Callable[[Peer], None],
                 out: Callable[[str], None], keepalive: Optional[float], interval: float = 5.0,
                 check_disjoint: bool = False):
        self.node = node
        self.path = path
        self.configure = configure
        self.out = out
        self.keepalive = keepalive
        self.interval = interval
        # With --tun linux every peer shares the routes, so two peers would overlap. The same check
        # that startup applies runs after each addition, and an overlapping peer is removed again.
        self.check_disjoint = check_disjoint
        self._next: Optional[float] = None
        self._last: Optional[bytes] = None

    def __call__(self, now: float) -> None:
        if self._next is not None and now < self._next:
            return
        self._next = now + self.interval
        try:
            with open(self.path, "rb") as f:
                content = f.read()
        except OSError as e:
            self.out(f"peer file check failed: {e.strerror or type(e).__name__}")
            return
        # Compare the contents, not size and mtime: an edit of the same length within one timestamp
        # tick would look unchanged, and a revocation must not be missed. The file is small.
        if content == self._last:
            return
        self._last = content
        try:
            entries = load_peer_entries(self.path)
        except (RuntimeError, OSError) as e:
            self.out(f"peer file reload refused, keeping current peers: {e}")
            return
        self.apply(entries)

    def apply(self, entries: Iterable[Tuple]) -> None:
        """Apply the file. Each entry is (x25519, ml-kem, psk); a pair is accepted and means no PSK field.
        A peer whose ML-KEM key or PSK changed is removed and added again, so the new key takes effect."""
        wanted = {e[0]: (e[1], e[2] if len(e) > 2 else b"") for e in entries}

        def effective_psk(psk: bytes) -> bytes:
            return psk if psk else self.node.psk     # an entry without a PSK field uses the node default

        removed = [pub for pub, peer in list(self.node.peers.items())
                   if pub not in wanted or peer.kem_pub != wanted[pub][0]
                   or peer.psk != effective_psk(wanted[pub][1])]
        for pub in removed:
            self.node.remove_peer(pub)
        added = 0
        for pub, (kem_pub, psk) in wanted.items():
            if pub not in self.node.peers:
                peer = self.node.add_peer(pub, keepalive=self.keepalive, kem_pub=kem_pub, psk=psk or None)
                self.configure(peer)
                if self.check_disjoint:
                    try:
                        self.node.check_allowed_ips_disjoint()
                    except ValueError as e:
                        self.node.remove_peer(pub)
                        self.out(f"peer file: a new peer was not added: {e}")
                        continue
                added += 1
        if added or removed:
            self.out(f"peer file applied: {added} peer(s) added, {len(removed)} removed")
