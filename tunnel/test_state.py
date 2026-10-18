"""Restart replay protection: the per-peer INIT timestamp is kept in a state file (vpn_state.TimestampStore).

The file is JSON {base64 peer public key: hex TAI64N}. Every test uses its own temp directory, which
is removed afterwards. Keys are generated in memory or passed in environment variables, never written.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from vpn_constants import MSG_RESP
from vpn_errors import StateFileError
from vpn_crypto import encode_key, generate_kem_keypair, generate_keypair, private_key_from_b64, public_key_from_b64
from vpn_state import state_key, TimestampStore
from vpn_handshake import make_response
from vpn_node import Node

TUNNEL_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(TUNNEL_DIR, "vpn_server.py")
A_ADDR = ("127.0.0.1", 1)     # client endpoint
B_ADDR = ("127.0.0.1", 2)     # server endpoint
T0 = 1000.0                   # fixed protocol clock (seconds)


def read_state(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


class RestartTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ioessa-state-test-")
        self.path = os.path.join(self.dir, "state.json")
        self.server_priv = X25519PrivateKey.generate()
        self.server_pub = Node(self.server_priv).pub
        # One ML-KEM key for the server across restarts, as a key file gives in production.
        self.server_kem_priv = mlkem.MLKEM768PrivateKey.generate()
        self.server_kem_pub = self.server_kem_priv.public_key().public_bytes_raw()
        self.client = Node(X25519PrivateKey.generate())
        self.cpeer = self.client.add_peer(self.server_pub, B_ADDR, kem_pub=self.server_kem_pub)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def make_server(self, state_path=None):
        """A server Node as vpn_server.main builds it. Each call is one process lifetime."""
        srv = Node(self.server_priv, ts_store=TimestampStore(state_path or self.path),
                   kem_priv=self.server_kem_priv)
        srv.add_peer(self.client.pub, A_ADDR, kem_pub=self.client.kem_pub)
        return srv

    def client_init(self, now):
        (init, _), = self.client.initiate(self.cpeer, now)
        return init

    def client_key_b64(self):
        return encode_key(self.client.pub)

    # ---- replay across restart
    def test_replayed_initiation_rejected_after_restart(self):
        captured = self.client_init(T0)
        srv = self.make_server()
        self.assertEqual(len(srv.handle(captured, A_ADDR, T0).send), 1)     # the real handshake
        srv2 = self.make_server()                                           # restart, same state file
        act = srv2.handle(captured, A_ADDR, T0)                             # the replay
        self.assertEqual(act.send, [])
        self.assertTrue(any("stale or replayed timestamp" in e for e in act.events), act.events)

    def test_newer_initiation_accepted_after_restart(self):
        srv = self.make_server()
        srv.handle(self.client_init(T0), A_ADDR, T0)
        srv2 = self.make_server()
        act = srv2.handle(self.client_init(T0 + 10), A_ADDR, T0 + 10)       # a real, newer INIT
        self.assertEqual(len(act.send), 1)
        self.assertEqual(act.send[0][0][0], MSG_RESP)

    def test_without_state_file_replay_is_accepted_after_restart(self):
        """The gap this file closes. With no state file, a restart clears the check (documents the default)."""
        captured = self.client_init(T0)
        srv = Node(self.server_priv, kem_priv=self.server_kem_priv)
        srv.add_peer(self.client.pub, A_ADDR, kem_pub=self.client.kem_pub)
        self.assertEqual(len(srv.handle(captured, A_ADDR, T0).send), 1)
        srv2 = Node(self.server_priv, kem_priv=self.server_kem_priv)
        srv2.add_peer(self.client.pub, A_ADDR, kem_pub=self.client.kem_pub)
        self.assertEqual(len(srv2.handle(captured, A_ADDR, T0).send), 1)    # accepted again

    # ---- ordering: on disk before the RESP
    def test_state_file_holds_timestamp_before_resp_is_built(self):
        captured = self.client_init(T0)
        srv = self.make_server()
        seen = {}
        real_make_response = make_response

        def spy(info, sender, psk, peer_kem_pub, cookie=None):
            seen["ts"] = info.timestamp
            seen["on_disk"] = read_state(self.path) if os.path.exists(self.path) else None
            return real_make_response(info, sender, psk, peer_kem_pub, cookie)

        with mock.patch("vpn_node.make_response", side_effect=spy):
            act = srv.handle(captured, A_ADDR, T0)
        self.assertEqual(len(act.send), 1)
        self.assertEqual(seen["on_disk"], {self.client_key_b64(): seen["ts"].hex()})
        self.assertEqual(read_state(self.path), {self.client_key_b64(): seen["ts"].hex()})

    def test_failed_state_write_sends_no_resp_and_changes_nothing(self):
        captured = self.client_init(T0)
        srv = self.make_server()
        with mock.patch("vpn_state.os.replace", side_effect=OSError("simulated disk error")):
            act = srv.handle(captured, A_ADDR, T0)
        self.assertEqual(act.send, [])
        self.assertTrue(any("state file write failed" in e for e in act.events), act.events)
        self.assertEqual(srv.peers[self.client.pub].last_init_ts, bytes(12))
        self.assertFalse(os.path.exists(self.path))
        # Once the disk works, the same INIT is accepted: it was never recorded.
        self.assertEqual(len(srv.handle(captured, A_ADDR, T0).send), 1)

    def test_only_public_keys_are_in_state_file(self):
        srv = self.make_server()
        srv.handle(self.client_init(T0), A_ADDR, T0)
        with open(self.path, "r", encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn(encode_key(self.server_priv.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())), text)
        self.assertIn(self.client_key_b64(), text)

    # ---- load behaviour
    def test_missing_state_file_starts_empty(self):
        store = TimestampStore(self.path)
        self.assertEqual(len(store), 0)
        self.assertEqual(store.get(self.client.pub), bytes(12))
        self.assertFalse(os.path.exists(self.path))        # created on first save, not on load

    def test_missing_directory_is_a_clear_error(self):
        bad = os.path.join(self.dir, "no-such-dir", "state.json")
        with self.assertRaises(StateFileError) as cm:
            TimestampStore(bad)
        self.assertIn("does not exist", str(cm.exception))

    def test_corrupted_state_file_refuses_to_load_and_is_not_reset(self):
        pub_ok = encode_key(bytes(31) + b"\x01")
        junk_cases = [
            b"{not json",
            b"[]",
            b"",
            json.dumps({"not base64!": "00" * 12}).encode(),
            json.dumps({encode_key(bytes(16)): "00" * 12}).encode(),               # key of 16 bytes
            json.dumps({pub_ok: "zz" * 12}).encode(),                              # not hex
            json.dumps({pub_ok: "00" * 8}).encode(),                               # too short
            json.dumps({pub_ok: 5}).encode(),                                      # not a string
            b"\xff\xfe\x00",                                                       # not UTF-8
        ]
        for junk in junk_cases:
            with open(self.path, "wb") as f:
                f.write(junk)
            with self.assertRaises(StateFileError) as cm:
                TimestampStore(self.path)
            self.assertIn("malformed", str(cm.exception))
            self.assertIn(self.path, str(cm.exception))
            with open(self.path, "rb") as f:
                self.assertEqual(f.read(), junk)           # not overwritten, not reset


class AtomicWriteTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ioessa-state-test-")
        self.path = os.path.join(self.dir, "state.json")
        self.pub = bytes(range(32))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_failed_replace_leaves_old_state_intact_and_loadable(self):
        store = TimestampStore(self.path)
        ts1 = bytes(11) + b"\x01"
        ts2 = bytes(11) + b"\x02"
        store.save(self.pub, ts1)
        before = read_bytes(self.path)
        with mock.patch("vpn_state.os.replace", side_effect=OSError("simulated crash during write")):
            with self.assertRaises(OSError):
                store.save(self.pub, ts2)
        self.assertEqual(read_bytes(self.path), before)                   # old file untouched
        self.assertEqual(TimestampStore(self.path).get(self.pub), ts1)    # still loads, old value
        self.assertEqual(store.get(self.pub), ts1)                        # memory did not move either
        self.assertEqual([f for f in os.listdir(self.dir) if f.endswith(".tmp")], [])   # temp removed

    def test_failed_write_before_replace_keeps_old_state(self):
        store = TimestampStore(self.path)
        ts1 = bytes(11) + b"\x05"
        store.save(self.pub, ts1)
        before = read_bytes(self.path)
        with mock.patch("vpn_state.os.fsync", side_effect=OSError("simulated fsync failure")):
            with self.assertRaises(OSError):
                store.save(self.pub, bytes(11) + b"\x06")
        self.assertEqual(read_bytes(self.path), before)
        self.assertEqual([f for f in os.listdir(self.dir) if f.endswith(".tmp")], [])


class StartupTests(unittest.TestCase):
    """Run vpn_server.py as a process with keys in environment variables only."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ioessa-state-test-")
        self.path = os.path.join(self.dir, "state.json")
        srv_priv, _ = generate_keypair()
        cli_priv, cli_pub = generate_keypair()
        srv_kem_seed, _ = generate_kem_keypair()
        _, cli_kem_pub = generate_kem_keypair()
        self.srv_b64 = encode_key(srv_priv)
        self.srv_kem_b64 = encode_key(srv_kem_seed)
        self.cli_b64 = encode_key(cli_pub)
        self.cli_entry = f"{self.cli_b64}:{encode_key(cli_kem_pub)}"

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_server(self, *args, env_state=None):
        env = dict(os.environ)
        env.pop("IOESSA_VPN_STATE_FILE", None)
        # The default state location is under the user profile. Point it at this test's directory.
        env["LOCALAPPDATA"] = self.dir
        env["XDG_STATE_HOME"] = self.dir
        env["IOESSA_VPN_PRIVATE_KEY"] = self.srv_b64
        env["IOESSA_VPN_KEM_KEY"] = self.srv_kem_b64
        env["IOESSA_VPN_PEER_PUBLIC_KEY"] = self.cli_entry
        if env_state is not None:
            env["IOESSA_VPN_STATE_FILE"] = env_state
        proc = subprocess.run([sys.executable, SERVER, "--port", "0", "--idle-timeout", "0.2", *args],
                              env=env, capture_output=True, text=True, timeout=60, cwd=TUNNEL_DIR)
        for stream in (proc.stdout, proc.stderr):
            self.assertNotIn(self.srv_b64, stream)                 # no key material in output
            self.assertNotIn(self.srv_kem_b64, stream)
        return proc

    def test_warning_without_state_file(self):
        proc = self.run_server("--no-state-file")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WARNING", proc.stderr)
        self.assertIn("--state-file", proc.stderr)
        self.assertIn("does NOT survive a restart", proc.stderr)

    def test_state_file_is_on_by_default_at_the_user_location(self):
        proc = self.run_server()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("WARNING", proc.stderr)
        default = os.path.join(self.dir, "ioessa-vpn", "state.json")
        self.assertIn("replay state: " + default, proc.stdout)

    def test_edited_state_file_stops_the_server(self):
        priv = private_key_from_b64(self.srv_b64)
        store = TimestampStore(self.path, state_key(priv))
        store.save(public_key_from_b64(self.cli_b64), bytes(12))
        raw = json.loads(read_bytes(self.path).decode("utf-8"))
        raw[self.cli_b64] = "00" * 11 + "01"                      # change a timestamp, keep the old tag
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(raw, f)
        proc = self.run_server("--state-file", self.path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("integrity check", proc.stderr)
        self.assertNotIn("listening", proc.stdout)

    def test_state_file_copied_from_another_server_is_refused(self):
        other_priv = X25519PrivateKey.generate()
        store = TimestampStore(self.path, state_key(other_priv))
        store.save(public_key_from_b64(self.cli_b64), bytes(12))
        proc = self.run_server("--state-file", self.path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("integrity check", proc.stderr)

    def test_flag_and_env_var_select_state_file_without_warning(self):
        proc = self.run_server("--state-file", self.path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("WARNING", proc.stderr)
        self.assertIn("replay state: " + os.path.abspath(self.path) + " (0 peer timestamp(s) loaded)", proc.stdout)
        proc = self.run_server(env_state=self.path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("WARNING", proc.stderr)

    def test_server_refuses_to_start_on_corrupted_state_file(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("{truncated")
        proc = self.run_server("--state-file", self.path)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("malformed", proc.stderr)
        self.assertNotIn("listening", proc.stdout)               # never bound a socket
        self.assertEqual(read_bytes(self.path), b"{truncated")


if __name__ == "__main__":
    unittest.main()
