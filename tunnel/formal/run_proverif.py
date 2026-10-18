"""Run the ProVerif model of the handshake in every attacker scenario and compare with the expected results.

Usage (from tunnel\\formal):  python run_proverif.py [variant ...]
ProVerif is found through the PROVERIF environment variable, then %LOCALAPPDATA%\\ioessa-vpn\\proverif,
then PATH. Exit code 0 means every result matched its expectation (including the expected attacks).
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "ioessa_handshake.pvt")
TIMEOUT = int(os.environ.get("PROVERIF_TIMEOUT", "1800"))    # seconds per query
JOBS = int(os.environ.get("PROVERIF_JOBS", "1"))             # ProVerif runs in parallel (memory-bound)
QUERIES = ["secrecy of data A->B", "secrecy of data B->A", "A authenticates B (injective)",
           "B authenticates A at first data", "B authenticates A at INIT"]

LEAK_DH = {"LEAK_EA": "out(c, eA);", "LEAK_EB": "out(c, eB);", "LEAK_NOW": "out(c, (sA, sB));"}
PHASE1 = {"LATER": "| (phase 1; out(c, (sA, sB, kskA, kskB, pskAB)))"}
T, F = True, False

# name: (description, PSK set?, marker fills, expected result per query)
VARIANTS = {
    "base_psk": ("no compromise, PSK set", True, {}, [T, T, T, T, T]),
    "base_nopsk": ("no compromise, no PSK", False, {}, [T, T, T, T, T]),
    "quantum_nopsk": ("X25519 broken (all DH secrets public), no PSK", False, LEAK_DH, [T, T, T, T, F]),
    "quantum_psk": ("X25519 broken, PSK set", True, LEAK_DH, [T, T, T, T, T]),
    "kem_broken": ("ML-KEM broken (both KEM private keys public), no PSK", False,
                   {"LEAK_NOW": "out(c, (kskA, kskB));"}, [T, T, T, T, T]),
    "kci_nopsk": ("B's static X25519 and ML-KEM keys stolen, no PSK", False,
                  {"LEAK_NOW": "out(c, (sB, kskB));"}, [F, T, F, T, F]),
    "fs": ("all long-term keys and the PSK stolen after the sessions", True, PHASE1, [T, T, T, T, T]),
    "pq_fs": ("X25519 broken, and all long-term keys stolen after the sessions", True,
              dict(LEAK_DH, **PHASE1), [F, F, T, T, T]),
}


def proverif() -> str:
    for p in (os.environ.get("PROVERIF"),
              os.path.join(os.environ.get("LOCALAPPDATA", ""), "ioessa-vpn", "proverif", "proverif2.05",
                           "proverif.exe"),
              shutil.which("proverif")):
        if p and os.path.isfile(p):
            return p
    sys.exit("ProVerif not found: set PROVERIF to the proverif executable")


def build(psk: bool, fills: dict) -> str:
    text = open(TEMPLATE, encoding="utf-8").read()
    text = text.replace("(*@PSK_DECL*)", "free pskAB: bitstring [private]." if psk else "")
    for name, value in fills.items():
        text = text.replace(f"(*@{name}*)", value)
    if not psk:
        text = text.replace("pskAB", "NOPSK")
    return text


def only_query(text: str, keep: int) -> str:
    """The model with every query but one commented out. One query per run is much faster."""
    queries = list(re.finditer(r"^query .*$", text, re.M))
    for i, m in reversed(list(enumerate(queries))):
        if i != keep:
            text = text[:m.start()] + "(* " + m.group(0) + " *)" + text[m.end():]
    return text


def check(job):
    """One ProVerif run: (variant, query index) -> (variant, query index, result, seconds)."""
    exe, name, q = job
    desc, psk, fills, expected = VARIANTS[name]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, f"{name}_q{q}.pv")
        with open(path, "w", encoding="utf-8") as f:
            f.write(only_query(build(psk, fills), q))
        start = time.monotonic()
        try:
            out = subprocess.run([exe, path], capture_output=True, text=True, timeout=TIMEOUT).stdout
        except subprocess.TimeoutExpired:
            return name, q, f"no answer within {TIMEOUT} s", TIMEOUT
    found = re.findall(r"^RESULT .* is (true|false|cannot be proved)\.", out, re.M)
    return name, q, found[0] if len(found) == 1 else "error: " + out[-300:], time.monotonic() - start


def main() -> int:
    from concurrent.futures import ThreadPoolExecutor
    exe = proverif()
    names = sys.argv[1:] or list(VARIANTS)
    jobs = [(exe, n, q) for n in names for q in range(len(QUERIES))]
    failed = []
    # Results print as they arrive (in job order), so a run that is stopped keeps what it finished.
    with ThreadPoolExecutor(max_workers=JOBS) as pool:
        for n, q, got, secs in pool.map(check, jobs):
            desc, _, _, expected = VARIANTS[n]
            want = expected[q]
            good = got == ("true" if want else "false")
            if not good:
                failed.append(f"{n}/{q}")
            note = "" if want else "  (attack expected)"
            print(f"{'ok ' if good else 'BAD'} {n} ({desc}) | {QUERIES[q]}: {got} ({secs:.0f} s){note}", flush=True)
    print("all results as expected" if not failed else f"unexpected: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
