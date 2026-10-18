"""Generate the static keys for the tunnel. Each side needs two key pairs:

  * X25519 (classical, 44 base64 characters each)
  * ML-KEM-768 (post-quantum, FIPS 203; the private key is a 64-byte seed, the public key 1184 bytes)

    python vpn_keygen.py --out key.txt      # write the files listed below (recommended)
    python vpn_keygen.py --stdout           # print both keys (secret; copy them into env vars)

Without --out or --stdout the program refuses to run, so a private key is never printed by accident.

With --out, these files are written (private files mode 0600 where supported):

  key.txt          X25519 private key          (IOESSA_VPN_PRIVATE_KEY_FILE)
  key.txt.pub      X25519 public key
  key.txt.kem      ML-KEM-768 private seed     (IOESSA_VPN_KEM_KEY_FILE)
  key.txt.peer     the peer entry to give the other side: <X25519 public>:<ML-KEM public>
  key.txt.created  creation date, ISO format in UTC (read by --max-key-age-days)

Keys are never written into the source. The other side needs your .peer entry, and you need theirs.

Use the key pair for this tunnel only. A key used in another protocol or application can be used
against this one (chosen protocol attacks, Anderson ch. 4).
"""
import argparse
import os
import sys
from datetime import datetime, timezone

from vpn_crypto import encode_key, generate_keypair, generate_kem_keypair
from vpn_keyfiles import CREATED_SUFFIX


def _create(path: str, text: str, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(text + "\n")


def main():
    ap = argparse.ArgumentParser(description="Generate tunnel static keys (X25519 and ML-KEM-768)")
    ap.add_argument("--out", help="write the key files next to this path (see the module docstring)")
    ap.add_argument("--stdout", action="store_true",
                    help="print the private keys to the terminal (secret; they stay in scrollback and shell history)")
    args = ap.parse_args()
    if not args.out and not args.stdout:
        ap.error("choose --out FILE (recommended: writes key files) or --stdout (prints the private keys)")
    priv, pub = generate_keypair()
    seed, kem_pub = generate_kem_keypair()
    peer = f"{encode_key(pub)}:{encode_key(kem_pub)}"
    if args.out:
        # Refuse to overwrite any of the files before creating any of them.
        names = [args.out, args.out + ".pub", args.out + ".kem", args.out + ".kem.pub", args.out + ".peer",
                 args.out + CREATED_SUFFIX]
        existing = [n for n in names if os.path.exists(n)]
        if existing:
            raise SystemExit(f"error: refusing to overwrite {existing[0]}")
        _create(args.out, encode_key(priv))
        _create(args.out + ".pub", encode_key(pub), mode=0o644)
        _create(args.out + ".kem", encode_key(seed))
        _create(args.out + ".kem.pub", encode_key(kem_pub), mode=0o644)
        _create(args.out + ".peer", peer, mode=0o644)
        _create(args.out + CREATED_SUFFIX, datetime.now(timezone.utc).date().isoformat(), mode=0o644)
        print(f"key files written next to {args.out} (see vpn_keygen.py for the list)")
    else:
        print(f"private: {encode_key(priv)}   (secret; set IOESSA_VPN_PRIVATE_KEY)")
        print(f"kem private: {encode_key(seed)}   (secret; set IOESSA_VPN_KEM_KEY)")
        print(f"peer entry: {peer}   (give to the peer; set IOESSA_VPN_PEER_PUBLIC_KEY)")
    print("Use this key pair for this tunnel only; do not reuse it in another protocol or application.",
          file=sys.stderr)


if __name__ == "__main__":
    main()
