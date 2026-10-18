"""Open issues 29 and 31: console lines carry a timestamp, and startup logs the peer file's digest.

Logs stay on stdout or stderr. There are no levels, no log file and no rotation, by design (README).
"""
import hashlib
import io
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import vpn_server

STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{4})? ")


class TimestampTests(unittest.TestCase):

    def test_say_writes_a_timestamp_before_the_message(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            vpn_server.say("hello")
        line = out.getvalue()
        self.assertRegex(line, STAMP)
        self.assertTrue(line.endswith(" hello\n"), line)

    def test_say_err_goes_to_stderr(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            vpn_server.say("warn", err=True)
        self.assertEqual(out.getvalue(), "")
        self.assertRegex(err.getvalue(), STAMP)

    def test_reject_counter_counts_the_raw_line_and_passes_the_stamped_one(self):
        seen = []
        counter = vpn_server.RejectCounter(seen.append)
        counter("dropped packet from ('10.0.0.1', 5): unknown index")
        self.assertEqual(counter.count, 1)
        self.assertEqual(seen, ["dropped packet from ('10.0.0.1', 5): unknown index"])


class PeerFileDigestTests(unittest.TestCase):

    def test_digest_is_sha256_of_the_file_bytes(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(b"peer-entry\n")
            self.assertEqual(vpn_server.peer_file_digest(path), hashlib.sha256(b"peer-entry\n").hexdigest())
        finally:
            os.remove(path)

    def test_startup_prints_the_peer_file_digest(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(b"x\n")
            argv = ["vpn_server.py", "--port", "0", "--bind", "127.0.0.1", "--peer-key-file", path]
            out = io.StringIO()
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(vpn_server, "load_static_private", return_value=X25519PrivateKey.generate()), \
                    mock.patch.object(vpn_server, "load_kem_private",
                                      return_value=mlkem.MLKEM768PrivateKey.generate()), \
                    mock.patch.object(vpn_server, "load_peer_entries", return_value=[]), \
                    mock.patch.object(vpn_server, "serve", side_effect=KeyboardInterrupt), \
                    mock.patch("sys.stdout", out), mock.patch("sys.stderr", io.StringIO()):
                vpn_server.main()
            digest = hashlib.sha256(b"x\n").hexdigest()
            self.assertIn(f"sha256 {digest}", out.getvalue())
            self.assertIn("0 peer(s)", out.getvalue())
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
