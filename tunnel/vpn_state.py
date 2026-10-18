"""Restart state (V-A): per-peer handshake timestamps kept in an HMAC-tagged file."""
import base64
import hmac
import json
import os
import tempfile
from typing import Dict, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from vpn_constants import LABEL_STATE, STATE_TAG_KEY, TS_LEN
from vpn_errors import StateFileError
from vpn_crypto import _h, _mac, encode_key


def state_key(static_priv: X25519PrivateKey) -> bytes:
    """Key for the state file's integrity tag, derived from this server's private key. It is secret and
    already on this machine, so no second secret is needed, and a copy of the file is useless elsewhere."""
    raw = static_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return _h(LABEL_STATE, raw)


def default_state_path() -> str:
    """Where the state file goes when no path is given. Windows: %LOCALAPPDATA%\\ioessa-vpn\\state.json.
    Elsewhere: $XDG_STATE_HOME/ioessa-vpn/state.json, or ~/.local/state/ioessa-vpn/state.json."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "ioessa-vpn", "state.json")


def _atomic_write(path: str, data: bytes) -> None:
    """Replace `path` with `data` in one step: temp file in the same directory, fsync, os.replace.
    A failure leaves the old file in place (and removes the temp file)."""
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if os.name != "nt":
        # Make the rename itself durable. Best effort: the new file is already in place.
        try:
            dfd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass


class TimestampStore:
    """Last accepted INIT timestamp per peer, kept on disk so replay protection survives a restart.

    File format: a JSON object, {base64 peer public key: hex TAI64N timestamp}. The file is read
    once, in __init__. A missing file means no entries. An unreadable or malformed file raises
    StateFileError, so the caller can refuse to start. Nothing is ever reset silently.

    save() writes the whole map atomically, and the in-memory map changes only after the write
    succeeds. Node calls save() before it accepts a timestamp and sends the RESP.
    """

    def __init__(self, path: str, key: Optional[bytes] = None):
        self.path = os.path.abspath(path)
        # With a key (see state_key), the file carries an HMAC over the peer map, so an edited or
        # copied file is refused at startup (open issue 30). Without a key, no tag is written.
        self._key = key
        self._data: Dict[bytes, bytes] = self._load()

    def _tag(self, data: Dict[bytes, bytes]) -> str:
        canonical = json.dumps({encode_key(k): v.hex() for k, v in data.items()}, sort_keys=True).encode("utf-8")
        return _mac(self._key, canonical).hex()

    def _load(self) -> Dict[bytes, bytes]:
        directory = os.path.dirname(self.path)
        if not os.path.isdir(directory):
            raise StateFileError(f"state file directory does not exist: {directory}")
        try:
            with open(self.path, "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            return {}
        except OSError as e:
            raise StateFileError(f"cannot read state file {self.path}: {e.strerror or e}") from None

        def bad(why: str) -> StateFileError:
            return StateFileError(f"state file {self.path} is malformed ({why}). Fix or move it. "
                                  f"The server will not reset it, because that would reopen replay.")

        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise bad("not valid JSON") from None
        if not isinstance(obj, dict):
            raise bad("top level is not an object")
        tag = obj.pop(STATE_TAG_KEY, None)
        data: Dict[bytes, bytes] = {}
        for key, val in obj.items():
            try:
                pub = base64.b64decode(key, validate=True)
            except (ValueError, TypeError):
                raise bad("a key is not base64") from None
            if len(pub) != 32:
                raise bad("a key does not decode to 32 bytes")
            if not isinstance(val, str) or len(val) != 2 * TS_LEN:
                raise bad("a timestamp is not 24 hex characters")
            try:
                data[pub] = bytes.fromhex(val)
            except ValueError:
                raise bad("a timestamp is not hex") from None
        if self._key is not None and (data or tag is not None):
            if tag is None:
                raise bad("it has no integrity tag")
            if not isinstance(tag, str) or not hmac.compare_digest(tag, self._tag(data)):
                raise StateFileError(f"state file {self.path} failed its integrity check. It was edited, or copied "
                                     f"from another server. Fix or move it. The server will not reset it.")
        return data

    def __len__(self) -> int:
        return len(self._data)

    def get(self, pub: bytes) -> bytes:
        """Last accepted timestamp for `pub`, or 12 zero bytes if none is on record."""
        return self._data.get(pub, bytes(TS_LEN))

    def save(self, pub: bytes, ts: bytes) -> None:
        """Record `ts` for `pub` on disk. Raises OSError, and then memory is unchanged."""
        new = dict(self._data)
        new[pub] = ts
        doc = {encode_key(k): v.hex() for k, v in new.items()}
        if self._key is not None:
            doc[STATE_TAG_KEY] = self._tag(new)
        _atomic_write(self.path, (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        self._data = new
