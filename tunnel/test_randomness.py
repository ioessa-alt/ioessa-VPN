"""Randomness checks for the tunnel. The reasoning is in RANDOMNESS_REVIEW.md.

The source scans use the ast module, so comments and strings cannot satisfy or trip them. They only
see names and calls, not runtime behaviour, so they are paired with behavioural tests below.
"""
import ast
import os
import random
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vpn_constants import COOKIE_SECRET_TIME, PSK_ENV
from vpn_crypto import _pub_raw, generate_keypair
from vpn_keyfiles import load_psk
from vpn_handshake import make_cookie_reply
from vpn_node import handshake_local, Node

HERE = Path(__file__).resolve().parent
# Production modules only: top-level, non-test. analysis/ is not scanned (it is a separate tool).
PRODUCTION = sorted(p for p in HERE.glob("*.py") if not p.name.startswith("test_"))

# Every randomness source the production code is allowed to call, as (receiver, attribute).
# If a new call appears, this test fails and the inventory in RANDOMNESS_REVIEW.md must be updated.
EXPECTED_RANDOM_CALLS = {
    ("os", "urandom"),                  # cookie secret, cookie salt
    ("secrets", "randbelow"),           # sender indices
    ("X25519PrivateKey", "generate"),   # static, ephemeral, and low-order-check keys
    ("MLKEM768PrivateKey", "generate"), # static ML-KEM-768 keys (Node, key generation)
}
RANDOM_ATTRS = {"urandom", "randbelow", "token_bytes", "token_hex", "token_urlsafe", "generate",
                "getrandbits", "randrange", "randint", "choice", "shuffle", "random", "uniform", "seed"}


def _tree(path: Path) -> ast.Module:
    # utf-8-sig: vpn_client.py starts with a BOM, which ast.parse rejects.
    return ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))


def _imported_modules(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield node.lineno, a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.lineno, node.module


class SourceScanTests(unittest.TestCase):
    def test_no_random_module_in_production_code(self):
        """Nothing in tunnel\\ imports the random module, so no key or nonce can come from it."""
        for path in PRODUCTION:
            for lineno, mod in _imported_modules(_tree(path)):
                self.assertNotEqual(mod.split(".")[0], "random", f"{path.name}:{lineno} imports {mod}")

    def test_no_random_names_referenced(self):
        """No bare name `random` is referenced (for example via an alias or a from-import)."""
        for path in PRODUCTION:
            for node in ast.walk(_tree(path)):
                if isinstance(node, ast.Name):
                    self.assertNotEqual(node.id, "random", f"{path.name}:{node.lineno}")

    def test_randomness_calls_are_exactly_the_inventory(self):
        """The set of randomness calls matches the inventory. Any new one is a review event."""
        found = set()
        where = {}
        for path in PRODUCTION:
            for node in ast.walk(_tree(path)):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in RANDOM_ATTRS):
                    continue
                # The receiver is a name (os.urandom) or the last attribute of one (mlkem.MLKEM768PrivateKey.generate).
                receiver = node.func.value
                if isinstance(receiver, ast.Name):
                    name = receiver.id
                elif isinstance(receiver, ast.Attribute):
                    name = receiver.attr
                else:
                    continue
                key = (name, node.func.attr)
                found.add(key)
                where.setdefault(key, f"{path.name}:{node.lineno}")
        self.assertEqual(found, EXPECTED_RANDOM_CALLS, f"unexpected or missing calls; seen at {where}")

    def test_no_fork_or_multiprocessing(self):
        """The prototype is single-process. A fork would copy live key and session state into a child."""
        for path in PRODUCTION:
            tree = _tree(path)
            for lineno, mod in _imported_modules(tree):
                self.assertNotEqual(mod.split(".")[0], "multiprocessing", f"{path.name}:{lineno}")
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, {"fork", "forkpty"}, f"{path.name}:{node.lineno}")


class SecretSizeTests(unittest.TestCase):
    def test_static_keypair_is_32_bytes(self):
        priv, pub = generate_keypair()
        self.assertEqual(len(priv), 32)
        self.assertEqual(len(pub), 32)

    def test_cookie_secret_is_32_nonzero_bytes(self):
        node = Node(X25519PrivateKey.generate())
        self.assertEqual(len(node._secret), 32)
        self.assertTrue(any(node._secret))

    def test_cookie_salt_is_32_bytes(self):
        """The salt is the 32 bytes at offset 8 of a cookie reply."""
        pub = _pub_raw(X25519PrivateKey.generate())
        msg = make_cookie_reply(pub, os.urandom(32),
                                     ("127.0.0.1", 1), bytes(16), 1)
        salt = msg[8:40]
        self.assertEqual(len(salt), 32)
        self.assertTrue(any(salt))

    def test_session_transport_keys_are_32_bytes(self):
        a, b = handshake_local()
        for node, other in ((a, b), (b, a)):
            sess = node.peers[other.pub].current
            self.assertIsNotNone(sess)
            self.assertEqual(len(sess.send_key), 32)
            self.assertEqual(len(sess.recv_key), 32)

    def test_psk_shorter_than_32_bytes_is_refused(self):
        with mock.patch.dict(os.environ, {PSK_ENV: "ab" * 31}):
            with self.assertRaises(RuntimeError):
                load_psk()

    def test_psk_of_32_bytes_is_accepted(self):
        with mock.patch.dict(os.environ, {PSK_ENV: "ab" * 32}):
            self.assertEqual(len(load_psk()), 32)

    def test_session_index_is_nonzero_32_bit(self):
        node = Node(X25519PrivateKey.generate())
        for _ in range(200):
            idx = node._new_index()
            self.assertTrue(1 <= idx <= 2**32 - 1)


class CookieSecretRotationTests(unittest.TestCase):
    def test_rotation_never_reuses_a_secret(self):
        clk = [1000.0]
        node = Node(X25519PrivateKey.generate(), clock=lambda: clk[0])
        history = [node._secret]
        for _ in range(5):
            clk[0] += COOKIE_SECRET_TIME
            current, previous = node._cookie_secrets(clk[0])
            self.assertNotIn(current, history, "a cookie secret was reused across rotations")
            self.assertEqual(previous, history[-1], "previous secret is not the one just retired")
            self.assertTrue(any(current))
            history.append(current)
        self.assertEqual(len(set(history)), len(history))

    def test_no_rotation_before_the_interval(self):
        clk = [1000.0]
        node = Node(X25519PrivateKey.generate(), clock=lambda: clk[0])
        before = node._secret
        clk[0] += COOKIE_SECRET_TIME - 1
        self.assertEqual(node._cookie_secrets(clk[0])[0], before)

    def test_two_nodes_get_different_cookie_secrets(self):
        a = Node(X25519PrivateKey.generate())
        b = Node(X25519PrivateKey.generate())
        self.assertNotEqual(a._secret, b._secret)


class BehaviourTests(unittest.TestCase):
    """Runtime checks that the source scans cannot make on their own."""

    def test_cookie_salt_comes_from_os_urandom(self):
        pub = _pub_raw(X25519PrivateKey.generate())
        with mock.patch.object(os, "urandom", wraps=os.urandom) as spy:
            make_cookie_reply(pub, os.urandom(32), ("127.0.0.1", 1), bytes(16), 1)
        spy.assert_called_with(32)

    def test_key_generation_ignores_the_random_module(self):
        """Seeding `random` to a fixed value must not make key generation repeat."""
        random.seed(12345)
        first = generate_keypair()
        random.seed(12345)
        second = generate_keypair()
        self.assertNotEqual(first[0], second[0])
        self.assertNotEqual(first[1], second[1])

    def test_cookie_salt_ignores_the_random_module(self):
        pub = _pub_raw(X25519PrivateKey.generate())
        random.seed(777)
        m1 = make_cookie_reply(pub, os.urandom(32), ("127.0.0.1", 1), bytes(16), 1)
        random.seed(777)
        m2 = make_cookie_reply(pub, os.urandom(32), ("127.0.0.1", 1), bytes(16), 1)
        self.assertNotEqual(m1[8:40], m2[8:40])

    def test_handshakes_do_not_repeat_keys(self):
        """Two runs of the same handshake share no transport key: no state is replayed."""
        a1, _ = handshake_local()
        a2, _ = handshake_local()
        k1 = a1.peers[next(iter(a1.peers))].current.send_key
        k2 = a2.peers[next(iter(a2.peers))].current.send_key
        self.assertNotEqual(k1, k2)


if __name__ == "__main__":
    unittest.main()
