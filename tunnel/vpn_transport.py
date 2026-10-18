"""Transport data messages (V-D6) and the anti-replay window."""
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from vpn_constants import (DATA_HDR, DATA_HDR_LEN, IPV4_NEXT_HEADER, MAX_ESP, MAX_INNER, MSG_DATA, REJECT_AFTER_TIME,
                           REKEY_AFTER_BYTES, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME, SEQ_MAX, TAG_LEN, WINDOW,
                           WIRE_VERSION)
from vpn_errors import ESPError, RekeyRequired


# ----------------------------------------------------------------- anti-replay
class ReplayWindow:
    """Sliding window over counters (V-D6, RFC 2401 App. C). Bit 0 is `top`; bit d is top-d."""

    def __init__(self):
        self.top = 0
        self.bitmap = 0

    def check(self, seq: int) -> Optional[str]:
        """Return None if seq is fresh, otherwise a reason. Does not change state."""
        if seq == 0:
            return "seq zero"
        if seq > self.top:
            return None
        d = self.top - seq
        if d >= WINDOW:
            return "out of window"
        if (self.bitmap >> d) & 1:
            return "replay"
        return None

    def update(self, seq: int) -> None:
        """Record seq. Call only after the packet's tag has verified."""
        if seq > self.top:
            shift = seq - self.top
            mask = (1 << WINDOW) - 1
            self.bitmap = (((self.bitmap << shift) | 1) & mask) if shift < WINDOW else 1
            self.top = seq
        elif self.top - seq < WINDOW:       # defensive: never set a bit outside the window
            self.bitmap |= 1 << (self.top - seq)


# ------------------------------------------------------------------ transport (V-D6)
@dataclass
class Session:
    """One transport keypair (V-D5). The indices identify it on the wire."""
    local_index: int
    remote_index: int
    send_key: bytes = field(repr=False)
    recv_key: bytes = field(repr=False)
    created: float
    initiator: bool
    send_counter: int = 0
    send_bytes: int = 0
    byte_limit: int = REKEY_AFTER_BYTES
    limit: int = REKEY_AFTER_MESSAGES
    rekey_after: float = REKEY_AFTER_TIME         # from the node's profile
    reject_after: float = REJECT_AFTER_TIME       # from the node's profile
    replay: ReplayWindow = field(default_factory=ReplayWindow)


def _data_nonce(counter: int) -> bytes:
    # V-D1 Aead nonce: 32 zero bits, then the 64-bit little-endian counter.
    return bytes(4) + counter.to_bytes(8, "little")


def seal_data(sess: Session, inner: bytes, now: float) -> bytes:
    """Encrypt one inner datagram (or an empty keepalive) into a DATA message (V-D6)."""
    if len(inner) > MAX_INNER:
        raise ESPError("inner datagram too large")
    if (sess.send_counter >= sess.limit or sess.send_bytes >= sess.byte_limit
            or now - sess.created >= sess.reject_after):
        raise RekeyRequired()
    sess.send_counter += 1
    sess.send_bytes += len(inner)
    counter = sess.send_counter
    header = DATA_HDR.pack(MSG_DATA, WIRE_VERSION, sess.remote_index, counter)
    # Trailer from the earlier prototype: padding 1, 2, 3, ..., pad length, next header. The
    # padded length is a multiple of 4. An empty inner datagram is a keepalive (V-E).
    pad = (-(len(inner) + 2)) % 4
    trailer = bytes(range(1, pad + 1)) + bytes([pad, IPV4_NEXT_HEADER])
    ct = ChaCha20Poly1305(sess.send_key).encrypt(_data_nonce(counter), inner + trailer, header)
    return header + ct


def open_data(sess: Session, packet: bytes) -> bytes:
    """Check, decrypt and un-pad a DATA message for this session. Returns the inner datagram.

    Order: size, counter range, read-only replay check, AEAD verify and decrypt, then the
    window update, so forged packets never move the window. An AEAD verifies and decrypts in
    one call, so the MAC check cannot be separated from decryption.
    """
    if len(packet) > MAX_ESP or len(packet) < DATA_HDR_LEN + TAG_LEN + 2:
        raise ESPError("bad size")
    counter = DATA_HDR.unpack_from(packet)[3]
    if counter > SEQ_MAX:
        raise ESPError("counter too large")
    reason = sess.replay.check(counter)
    if reason:
        raise ESPError(reason)
    try:
        pt = ChaCha20Poly1305(sess.recv_key).decrypt(_data_nonce(counter), packet[DATA_HDR_LEN:],
                                                     packet[:DATA_HDR_LEN])
    except InvalidTag:
        raise ESPError("auth failed") from None
    sess.replay.update(counter)
    pad_len, next_hdr = pt[-2], pt[-1]
    if next_hdr != IPV4_NEXT_HEADER or pad_len > len(pt) - 2:
        raise ESPError("bad trailer")
    if pt[len(pt) - 2 - pad_len:len(pt) - 2] != bytes(range(1, pad_len + 1)):
        raise ESPError("bad padding")
    return pt[:len(pt) - 2 - pad_len]
