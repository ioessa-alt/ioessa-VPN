"""Handshake messages (V-D): INIT, RESP and COOKIE reply, with mac1 and mac2."""
import hmac
import ipaddress
import os
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vpn_constants import (CONSTRUCTION, COOKIE_LEN, HS_COOKIE_HDR, HS_FAIL, HS_INIT_HDR, HS_RESP_HDR, IDENTIFIER,
                           INIT_LEN, INIT_MAC1, LABEL_COOKIE, LABEL_I2R, LABEL_MAC1, LABEL_R2I, MSG_COOKIE, MSG_INIT,
                           MSG_RESP, RESP_LEN, RESP_MAC1, TAG_LEN, WIRE_VERSION)
from vpn_errors import HandshakeError
from vpn_crypto import _aead_open, _aead_seal, _decaps, _dh, _encaps, _h, _kdf, _mac, _pub_raw


def _init_chain(responder_pub: bytes, responder_kem_pub: bytes) -> Tuple[bytes, bytes]:
    """Initial chaining key and hash for IK, with the responder's static keys mixed in (V-D2).
    The ML-KEM key is hashed in too, so both sides must hold the same post-quantum key. The PSK is
    not here: it belongs to one peer, and is mixed in once the initiator's static key is known."""
    ck = _h(CONSTRUCTION)                                   # Construction (V-D1)
    h = _h(ck, IDENTIFIER)                                  # Hi = Hash(Ci | Identifier)
    h = _h(h, responder_pub)                                # Hi = Hash(Hi | Spub_r)
    h = _h(h, responder_kem_pub)                            # Hi = Hash(Hi | ML-KEM Spub_r)
    return ck, h


def _mac1_key(pub: bytes) -> bytes:
    """Key for msg.mac1: the receiver's public key only. It is a cheap filter, not authentication,
    so it does not need the PSK, and the receiver can check it before it knows which peer sent the INIT."""
    return _h(LABEL_MAC1, pub)


def _cookie_key(pub: bytes, salt: bytes) -> bytes:
    """Key that encrypts a cookie reply: the responder's public key and a random salt (V-C)."""
    return _h(LABEL_COOKIE, pub, salt)


def _ip_bytes(addr: tuple) -> bytes:
    """The cookie binds to the source IP only. Ports can change under NAT and roaming (II-A)."""
    return ipaddress.ip_address(addr[0]).packed


def _cookie_tau(secret: bytes, addr: tuple) -> bytes:
    """tau = Mac(R_m, A_m'), the cookie for a source address (V-D7)."""
    return _mac(secret, _ip_bytes(addr))


def _check_mac1(msg: bytes, off: int, pub: bytes) -> bool:
    return hmac.compare_digest(msg[off:off + TAG_LEN], _mac(_mac1_key(pub), msg[:off]))


def _check_mac2(msg: bytes, off: int, secs: List[bytes], addr: tuple) -> bool:
    """mac2 is keyed by a cookie for this source. Current and previous secret are accepted,
    so a rotation does not invalidate a cookie that is still fresh (V-C)."""
    for secret in secs:
        tau = _cookie_tau(secret, addr)
        if hmac.compare_digest(msg[off + TAG_LEN:off + 2 * TAG_LEN], _mac(tau, msg[:off + TAG_LEN])):
            return True
    return False


def _header_ok(msg: bytes, mtype: int) -> bool:
    """Type, wire version and reserved bytes. They are part of the message, so a message of one type
    cannot be replayed as another (reflection, Aumasson ch.11), and another version is refused."""
    return len(msg) >= 4 and msg[0] == mtype and msg[1] == WIRE_VERSION and msg[2:4] == bytes(2)


def _check_shape(msg: bytes, mtype: int, length: int) -> None:
    if len(msg) != length or not _header_ok(msg, mtype):
        raise HandshakeError(HS_FAIL, "message shape (length, type, version or reserved bytes)")


# ------------------------------------------------------------------ handshake (V-D)
@dataclass
class InitState:
    """What the initiator keeps between INIT and RESP: Ci, Hi, the ephemeral key, and the sender index."""
    sender: int
    peer_pub: bytes
    psk: bytes = field(repr=False)
    ck: bytes = field(repr=False)
    h: bytes = field(repr=False)
    eph_priv: X25519PrivateKey = field(repr=False)
    static_priv: X25519PrivateKey = field(repr=False)
    mac1: bytes = field(repr=False)     # the mac1 of this INIT; cookie replies are bound to it
    kem_priv: mlkem.MLKEM768PrivateKey = field(repr=False)   # our static ML-KEM key, for the RESP


@dataclass
class InitInfo:
    """What the responder learns from an INIT. After consume_initiation it knows the initiator's
    static key. After finish_initiation, with that peer's PSK, it also has the timestamp."""
    peer_pub: bytes = field(repr=False)
    sender: int
    eph_pub: bytes = field(repr=False)
    ck: bytes = field(repr=False)
    h: bytes = field(repr=False)
    enc_ts: bytes = field(repr=False, default=b"")
    timestamp: bytes = field(repr=False, default=b"")


def make_initiation(static_priv: X25519PrivateKey, static_pub: bytes, kem_priv: mlkem.MLKEM768PrivateKey,
                    peer_pub: bytes, peer_kem_pub: bytes, psk: bytes,
                    sender: int, timestamp: bytes, cookie: Optional[bytes] = None) -> Tuple[bytes, InitState]:
    """Build the INIT message (V-D2). The initiator encapsulates to the responder's static ML-KEM-768
    key, so only the holder of that private key can derive the keys that open the AEAD. The
    initiator's static key is encrypted (identity hiding). `psk` is this peer's pre-shared key. It is
    mixed in after the static key, so the responder learns which peer this is before it needs the PSK."""
    ck, h = _init_chain(peer_pub, peer_kem_pub)
    eph = X25519PrivateKey.generate()
    eph_pub = _pub_raw(eph)
    h = _h(h, eph_pub)
    ss, ct = _encaps(peer_kem_pub)
    h = _h(h, ct)
    ck, _ = _kdf(ck, ss)                                    # mix the post-quantum secret
    ck, k = _kdf(ck, _dh(eph, peer_pub))
    enc_static = _aead_seal(k, static_pub, h)
    h = _h(h, enc_static)
    ck, _ = _kdf(ck, psk)                                   # mix this peer's PSK (empty when none)
    ck, k = _kdf(ck, _dh(static_priv, peer_pub))
    enc_ts = _aead_seal(k, timestamp, h)
    h = _h(h, enc_ts)
    body = HS_INIT_HDR.pack(MSG_INIT, WIRE_VERSION, sender) + eph_pub + ct + enc_static + enc_ts
    mac1 = _mac(_mac1_key(peer_pub), body)
    body += mac1
    mac2 = _mac(cookie, body) if cookie else bytes(TAG_LEN)   # zero unless a fresh cookie is held
    msg = body + mac2
    return msg, InitState(sender, peer_pub, psk, ck, h, eph, static_priv, mac1, kem_priv)


def consume_initiation(static_priv: X25519PrivateKey, own_pub: bytes, own_kem_pub: bytes,
                       kem_priv: mlkem.MLKEM768PrivateKey, msg: bytes) -> InitInfo:
    """Responder, step 1: decapsulate with our ML-KEM key and decrypt the initiator's static key.
    The timestamp is left for finish_initiation, once the peer (and its PSK) is known. The mac1 must
    already be checked."""
    _check_shape(msg, MSG_INIT, INIT_LEN)
    sender = struct.unpack_from("<I", msg, 4)[0]
    eph = msg[8:40]
    ct = msg[40:1128]
    enc_static = msg[1128:1176]
    enc_ts = msg[1176:INIT_MAC1]
    ck, h = _init_chain(own_pub, own_kem_pub)
    h = _h(h, eph)
    h = _h(h, ct)
    ck, _ = _kdf(ck, _decaps(kem_priv, ct))
    ck, k = _kdf(ck, _dh(static_priv, eph))
    peer_pub = _aead_open(k, enc_static, h, "static key of the initiator (wrong responder key or tampering)")
    h = _h(h, enc_static)
    return InitInfo(peer_pub, sender, eph, ck, h, enc_ts)


def finish_initiation(info: InitInfo, static_priv: X25519PrivateKey, psk: bytes) -> InitInfo:
    """Responder, step 2: mix the PSK of the identified peer, then decrypt the timestamp (V-A).
    A wrong PSK fails here, at the timestamp AEAD, so the failure is silent like any other."""
    ck, _ = _kdf(info.ck, psk)
    ck, k = _kdf(ck, _dh(static_priv, info.peer_pub))
    h = info.h
    timestamp = _aead_open(k, info.enc_ts, h, "INIT timestamp (wrong PSK or tampering)")
    h = _h(h, info.enc_ts)
    return InitInfo(info.peer_pub, info.sender, info.eph_pub, ck, h, info.enc_ts, timestamp)



def make_response(info: InitInfo, sender: int, psk: bytes, peer_kem_pub: bytes,
                  cookie: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """Responder: build RESP (V-D3). Returns (message, key I->R, key R->I).

    The responder encapsulates to the initiator's static ML-KEM key, so the RESP proves the responder
    holds the initiator's key material as well: the initiator must decapsulate to finish."""
    eph = X25519PrivateKey.generate()
    eph_pub = _pub_raw(eph)
    ck, h = info.ck, info.h
    if psk:
        ck, _ = _kdf(ck, eph_pub)
    h = _h(h, eph_pub)
    ss, ct = _encaps(peer_kem_pub)
    h = _h(h, ct)
    ck, _ = _kdf(ck, _dh(eph, info.eph_pub))           # DH(Epriv_r, Epub_i)
    ck, _ = _kdf(ck, _dh(eph, info.peer_pub))          # DH(Epriv_r, Spub_i)
    ck, k = _kdf(ck, ss)                               # mix the post-quantum secret
    empty = _aead_seal(k, b"", h)                      # key confirmation for the responder
    body = HS_RESP_HDR.pack(MSG_RESP, WIRE_VERSION, sender, info.sender) + eph_pub + ct + empty
    body += _mac(_mac1_key(info.peer_pub), body)
    body += _mac(cookie, body) if cookie else bytes(TAG_LEN)
    k_i2r, k_r2i = _transport_keys(ck)
    return body, k_i2r, k_r2i


def consume_response(st: InitState, msg: bytes) -> Tuple[int, bytes, bytes]:
    """Initiator: check RESP against the saved state (V-D3). Returns (remote index, I->R, R->I)."""
    _check_shape(msg, MSG_RESP, RESP_LEN)
    if struct.unpack_from("<I", msg, 8)[0] != st.sender:
        raise HandshakeError(HS_FAIL, "RESP receiver index does not match our INIT")
    remote = struct.unpack_from("<I", msg, 4)[0]
    eph_r = msg[12:44]
    ct = msg[44:1132]
    empty = msg[1132:RESP_MAC1]
    ck, h = st.ck, st.h
    if st.psk:
        ck, _ = _kdf(ck, eph_r)
    h = _h(h, eph_r)
    h = _h(h, ct)
    ck, _ = _kdf(ck, _dh(st.eph_priv, eph_r))          # DH(Epriv_i, Epub_r)
    ck, _ = _kdf(ck, _dh(st.static_priv, eph_r))       # DH(Spriv_i, Epub_r)
    ck, k = _kdf(ck, _decaps(st.kem_priv, ct))         # mix the post-quantum secret
    _aead_open(k, empty, h, "responder key confirmation (wrong key or transcript)")  # raises if the responder did not prove itself
    k_i2r, k_r2i = _transport_keys(ck)
    return remote, k_i2r, k_r2i


def _transport_keys(ck: bytes) -> Tuple[bytes, bytes]:
    """Transport keys from the final chaining key (V-D5). Each direction has its own label."""
    k_i2r, _ = _kdf(ck, LABEL_I2R)
    k_r2i, _ = _kdf(ck, LABEL_R2I)
    return k_i2r, k_r2i


def make_cookie_reply(own_pub: bytes, secret: bytes, src: tuple,
                      init_mac1: bytes, init_sender: int) -> bytes:
    """Cookie reply (V-D7). The cookie is encrypted with a key from our public key and a random salt.
    init_mac1 is the associated data, which binds the reply to the INIT that caused it."""
    tau = _cookie_tau(secret, src)
    salt = os.urandom(32)
    enc = _aead_seal(_cookie_key(own_pub, salt), tau, init_mac1)
    return HS_COOKIE_HDR.pack(MSG_COOKIE, WIRE_VERSION, init_sender) + salt + enc


def consume_cookie(st: InitState, msg: bytes) -> bytes:
    """Initiator: decrypt a cookie reply for our pending INIT. Returns the cookie (tau)."""
    _check_shape(msg, MSG_COOKIE, COOKIE_LEN)
    if struct.unpack_from("<I", msg, 4)[0] != st.sender:
        raise HandshakeError(HS_FAIL, "cookie receiver index does not match our INIT")
    salt = msg[8:40]
    enc = msg[40:72]
    return _aead_open(_cookie_key(st.peer_pub, salt), enc, st.mac1, "cookie reply (tampering)")
