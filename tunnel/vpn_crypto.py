"""Crypto primitives (V-D1) and key encoding. Nothing here implements a cipher or a MAC itself."""
import base64
import hashlib
import hmac
import struct
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from vpn_constants import HS_FAIL, KEM_EK_LEN, KEM_SEED_LEN, TAG_LEN, ZERO_NONCE
from vpn_errors import HandshakeError


# ------------------------------------------------------------------ primitives
def _h(*parts: bytes) -> bytes:
    """Hash(input, 32) with BLAKE2s (V-D1)."""
    return hashlib.blake2s(b"".join(parts)).digest()


def _mac(key: bytes, data: bytes, size: int = TAG_LEN) -> bytes:
    """Mac(key, input, length): keyed BLAKE2s, or plain BLAKE2s when the key is empty (V-D1)."""
    if key:
        return hashlib.blake2s(data, key=key, digest_size=size).digest()
    return hashlib.blake2s(data, digest_size=size).digest()


def _hmac_b2s(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def _kdf(key: bytes, inp: bytes) -> Tuple[bytes, bytes]:
    """Kdf(key, input) from V-D1: tau = Hmac(key, input); t1 = Hmac(tau, 0x1); t2 = Hmac(tau, t1 | 0x2).

    This is HKDF over HMAC-BLAKE2s, returning two 32-byte values (chaining key, key)."""
    tau = _hmac_b2s(key, inp)
    t1 = _hmac_b2s(tau, b"\x01")
    t2 = _hmac_b2s(tau, t1 + b"\x02")
    return t1, t2


def _aead_seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(ZERO_NONCE, plaintext, aad)


def _aead_open(key: bytes, ciphertext: bytes, aad: bytes, stage: str = "AEAD") -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(ZERO_NONCE, ciphertext, aad)
    except InvalidTag:
        raise HandshakeError(HS_FAIL, stage) from None


def _encaps(kem_pub: bytes) -> Tuple[bytes, bytes]:
    """ML-KEM-768 encapsulation to a static public key. Returns (shared secret, ciphertext)."""
    try:
        ss, ct = mlkem.MLKEM768PublicKey.from_public_bytes(kem_pub).encapsulate()
    except ValueError:
        raise HandshakeError(HS_FAIL, "ML-KEM encapsulation (peer's key is invalid)") from None
    return ss, ct


def _decaps(kem_priv: mlkem.MLKEM768PrivateKey, ct: bytes) -> bytes:
    """ML-KEM-768 decapsulation. A wrong ciphertext gives a wrong secret (implicit rejection), so the
    AEAD checks that follow are what reject it."""
    try:
        return kem_priv.decapsulate(ct)
    except ValueError:
        raise HandshakeError(HS_FAIL, "ML-KEM decapsulation") from None


def _pub_raw(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _dh(priv: X25519PrivateKey, pub: bytes) -> bytes:
    """DH(private, public) (V-D1). Low-order points are refused (Aumasson ch.12)."""
    try:
        shared = priv.exchange(X25519PublicKey.from_public_bytes(pub))
    except ValueError:
        raise HandshakeError(HS_FAIL, "X25519 exchange (invalid point)") from None
    if hmac.compare_digest(shared, bytes(len(shared))):   # explicit all-zero check, independent of the library, constant-time
        raise HandshakeError(HS_FAIL, "X25519 exchange (all-zero output, low-order point)")
    return shared


def _is_low_order(pub: bytes) -> bool:
    """True if `pub` is a small-order X25519 point (Ch 5, small subgroup attacks). The clamped
    scalar kills the point's small order, so the output is all-zero and the library refuses it.
    Configured keys are checked with this, so a bad key fails at load time, not inside poll()."""
    try:
        X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(pub))
    except ValueError:
        return True
    return False


def _tai64n_to_unix(ts: bytes) -> float:
    """Unix time in seconds from a TAI64N timestamp, the inverse of _tai64n (to within a nanosecond)."""
    secs, nanos = struct.unpack(">QI", ts)
    return (secs - (1 << 62) - 10) + nanos / 1e9


def _tai64n(now_ns: int) -> bytes:
    """Timestamp() (V-A, V-D1): TAI64N, big-endian, so two values compare with memcmp."""
    secs, nanos = divmod(now_ns, 10**9)
    return struct.pack(">QI", (1 << 62) + 10 + secs, nanos)


# ------------------------------------------------------------------ keys and config
def new_private_key() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (private, public) as 32 raw bytes each."""
    priv = X25519PrivateKey.generate()
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()), _pub_raw(priv)


def encode_key(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def private_key_from_b64(text: str) -> X25519PrivateKey:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except ValueError:
        raise RuntimeError("private key is not valid base64") from None
    if len(raw) != 32:
        raise RuntimeError("private key must decode to 32 bytes")
    return X25519PrivateKey.from_private_bytes(raw)


def generate_kem_keypair() -> Tuple[bytes, bytes]:
    """Return (seed, public key) for a static ML-KEM-768 key: 64 and 1184 raw bytes."""
    priv = mlkem.MLKEM768PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def kem_private_from_b64(text: str) -> mlkem.MLKEM768PrivateKey:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except ValueError:
        raise RuntimeError("ML-KEM private key is not valid base64") from None
    if len(raw) != KEM_SEED_LEN:
        raise RuntimeError("ML-KEM private key must decode to a 64-byte seed")
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(raw)


def kem_public_from_b64(text: str) -> bytes:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except ValueError:
        raise RuntimeError("ML-KEM public key is not valid base64") from None
    if len(raw) != KEM_EK_LEN:
        raise RuntimeError("ML-KEM public key must decode to 1184 bytes")
    try:
        mlkem.MLKEM768PublicKey.from_public_bytes(raw)     # FIPS 203 key check
    except ValueError:
        raise RuntimeError("ML-KEM public key is malformed") from None
    return raw


def public_key_from_b64(text: str) -> bytes:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except ValueError:
        raise RuntimeError("public key is not valid base64") from None
    if len(raw) != 32 or _is_low_order(raw):
        raise RuntimeError("public key must decode to 32 bytes that are not a low-order point")
    return raw


def check_psk(key: bytes) -> bytes:
    """A pre-shared key is empty (no PSK) or at least 32 bytes and not all zeros (see load_psk)."""
    if not key:
        return key
    if len(key) < 32:
        raise ValueError("pre-shared key must be at least 32 bytes")
    if not any(key):
        raise ValueError("pre-shared key must not be all zeros")
    return key
