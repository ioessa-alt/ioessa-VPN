"""Loading keys, peer entries and the PSK from files and env vars, with permission checks."""
import os
import re
import subprocess
from datetime import date, datetime, timezone
from typing import Callable, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vpn_constants import KEM_KEY_ENV, KEM_KEY_FILE_ENV, KEY_ENV, KEY_FILE_ENV, PEER_ENV, PSK_ENV
from vpn_crypto import check_psk, kem_private_from_b64, kem_public_from_b64, private_key_from_b64, public_key_from_b64

WINDOWS_TRUSTED = ("SYSTEM", "Administrators")      # principals allowed on a key file, besides the user
# icacls tokens that grant nothing: inheritance flags, (N) for no access, and the integrity-label policies (NW, NR, NX) of a
# "Mandatory Label" line. Every other token is a right.
WINDOWS_INHERIT_FLAGS = {"I", "OI", "CI", "IO", "NP", "N", "NW", "NR", "NX"}
_ICACLS_ACE = re.compile(r"([^:]+):((?:\([^)]*\))+)")


def _parse_icacls(text: str, path: str = "") -> List[Tuple[str, frozenset]]:
    """(principal, grant rights) for each allow ACE in `icacls <path>` output. The path itself is
    removed first, since the first ACE can share its line. Principal names keep only the part
    after the last backslash, so `BUILTIN\\Administrators` is `Administrators`. Inheritance flags
    such as (I) and (OI) grant nothing and are dropped. DENY ACEs are skipped."""
    entries = []
    for line in text.splitlines():
        if path:
            line = line.replace(path, "")
        for who, rest in _ICACLS_ACE.findall(line):
            tokens = re.findall(r"\(([^)]*)\)", rest)
            if "DENY" in tokens:
                continue
            # Specific rights print comma-joined in one group, e.g. (RD,REA,RA): split them (SELF_AUDIT S1).
            rights = frozenset(r for t in tokens for r in t.split(",") if r and r not in WINDOWS_INHERIT_FLAGS)
            entries.append((who.rsplit("\\", 1)[-1].strip(), rights))
    return entries


def _check_windows_acl(path: str, run: Callable = subprocess.run, user: Optional[str] = None) -> None:
    """Windows: refuse a private key file that grants access to anyone other than the current
    user, SYSTEM or Administrators. Reads the DACL with `icacls`. Fails closed: if the ACL cannot
    be read or has no entries, the load is refused. Principal names are matched in English, so
    on a localized Windows the check may refuse until the extra entries are removed."""
    try:
        result = run(["icacls", path], capture_output=True, text=True, check=False)
    except OSError as e:
        raise RuntimeError(f"cannot run icacls to check {path}: {e}") from None
    if result.returncode != 0:
        raise RuntimeError(f"cannot read the ACL of {path} (icacls exit {result.returncode})")
    entries = _parse_icacls(result.stdout, path)
    if not entries:
        raise RuntimeError(f"no ACL entries found for {path}; refusing to load it")
    allowed = {(user or os.environ.get("USERNAME") or "").lower(), *(p.lower() for p in WINDOWS_TRUSTED)}
    stray = sorted({who for who, rights in entries if rights and who.lower() not in allowed})
    if stray:
        raise RuntimeError(f"private key file {path} grants access to {', '.join(stray)}. "
                           f"Remove those entries (icacls) and try again")


def _check_key_file_mode(path: str, posix: bool = os.name != "nt", stat: Callable = os.stat) -> None:
    """POSIX: refuse a private key file that any group or other user can read or write.
    Windows: refuse a key file whose ACL grants access to anyone else (see _check_windows_acl).
    `posix` and `stat` are parameters so the POSIX rule can be tested on any platform."""
    if not posix:
        _check_windows_acl(path)
        return
    mode = stat(path).st_mode & 0o777
    if mode & 0o077:
        raise RuntimeError(f"private key file {path} is accessible to group or others (mode {mode:03o}). "
                           f"Restrict it to your user (chmod 600) and try again")


def load_static_private(path: Optional[str] = None) -> X25519PrivateKey:
    """Local static private key from `path`, else IOESSA_VPN_PRIVATE_KEY_FILE, else
    IOESSA_VPN_PRIVATE_KEY. The value is never printed."""
    path = path or os.environ.get(KEY_FILE_ENV) or None
    if path:
        _check_key_file_mode(path)
        with open(path, "r", encoding="ascii") as f:
            text = f.read()
    else:
        text = os.environ.get(KEY_ENV, "")
    if not text.strip():
        raise RuntimeError(f"no private key: pass --key-file or set {KEY_ENV} (see vpn_keygen.py)")
    return private_key_from_b64(text)


def load_peer_entries(path: Optional[str] = None) -> List[Tuple[bytes, bytes, bytes]]:
    """Peer entries from `path` or IOESSA_VPN_PEER_PUBLIC_KEY (comma or newline separated). Each entry is
    `<X25519 public key>:<ML-KEM-768 public key>` with an optional third field, `:<PSK in hex>`, which is
    that peer's pre-shared key. Without it the entry uses the node's default PSK. Returns
    (x25519, ml-kem, psk) triples, psk b"" when the entry has none. A file that holds a PSK gets the
    same permission check as a private key file (SELF_AUDIT S2)."""
    if path:
        with open(path, "r", encoding="ascii") as f:
            text = f.read()
    else:
        text = os.environ.get(PEER_ENV, "")
    entries = [e.strip() for e in text.replace("\n", ",").split(",") if e.strip()]
    if not entries:
        raise RuntimeError(f"no peer public key: pass --peer-key-file or set {PEER_ENV}")
    out = []
    for entry in entries:
        fields = entry.split(":")
        if len(fields) not in (2, 3):
            raise RuntimeError("each peer entry needs an ML-KEM key too: <X25519 key>:<ML-KEM key>[:<PSK hex>]")
        psk = b""
        if len(fields) == 3:
            try:
                psk = check_psk(bytes.fromhex(fields[2]))
            except ValueError as e:
                raise RuntimeError(f"peer entry PSK: {e}") from None
            if not psk:
                raise RuntimeError("peer entry PSK is empty; drop the field to use the default")
        out.append((public_key_from_b64(fields[0]), kem_public_from_b64(fields[1]), psk))
    if path and any(e[2] for e in out):
        try:
            _check_key_file_mode(path)
        except RuntimeError as e:
            raise RuntimeError(f"peer file holds PSKs: {e}") from None
    return out


def load_peer_publics(path: Optional[str] = None) -> List[Tuple[bytes, bytes]]:
    """(x25519, ml-kem) pairs for the peer entries. See load_peer_entries for the format and the PSK field."""
    return [(pub, kem) for pub, kem, _ in load_peer_entries(path)]


def load_kem_private(path: Optional[str] = None) -> mlkem.MLKEM768PrivateKey:
    """Local static ML-KEM-768 key from `path`, else IOESSA_VPN_KEM_KEY_FILE, else IOESSA_VPN_KEM_KEY.
    The value is never printed."""
    path = path or os.environ.get(KEM_KEY_FILE_ENV) or None
    if path:
        _check_key_file_mode(path)
        with open(path, "r", encoding="ascii") as f:
            text = f.read()
    else:
        text = os.environ.get(KEM_KEY_ENV, "")
    if not text.strip():
        raise RuntimeError(f"no ML-KEM key: pass --kem-key-file or set {KEM_KEY_ENV} (see vpn_keygen.py)")
    return kem_private_from_b64(text)


CREATED_SUFFIX = ".created"      # keygen writes the key's creation date (ISO, UTC) to <key file>.created


def check_key_age(path: Optional[str], max_days: int, today: Optional[date] = None) -> None:
    """Refuse a static key older than `max_days` (open issue 5). 0 turns the limit off, which is the default.
    The date comes from the .created file that vpn_keygen.py writes next to the key. A key with no valid
    date cannot be aged, so it is refused while a limit is set. A key from an environment variable has no
    file, so it cannot be aged either."""
    if max_days <= 0:
        return
    if not path:
        raise RuntimeError("the key age limit needs a key file (--key-file); an environment key cannot be aged")
    try:
        with open(path + CREATED_SUFFIX, "r", encoding="ascii") as f:
            created = date.fromisoformat(f.read().strip())
    except (OSError, ValueError):
        raise RuntimeError(f"cannot check the age of {path}: no valid {CREATED_SUFFIX} file. Create keys with "
                           f"vpn_keygen.py --out, or turn the limit off") from None
    age = ((today or datetime.now(timezone.utc).date()) - created).days
    if age > max_days:
        raise RuntimeError(f"key {path} is {age} days old, past the {max_days}-day limit. Rotate it with "
                           f"vpn_keygen.py --out NEWFILE, then update the peers")


def load_psk() -> bytes:
    """The optional pre-shared key (hex, at least 32 bytes). Used only with --use-psk."""
    raw = os.environ.get(PSK_ENV, "")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        key = b""
    if len(key) < 32:
        raise RuntimeError(f"set {PSK_ENV} to at least 64 hex characters")
    if not any(key):
        # An all-zero key is a known value, so it gives no secrecy at all.
        raise RuntimeError(f"{PSK_ENV} must not be all zeros; generate a random key with secrets.token_hex(32)")
    return key
