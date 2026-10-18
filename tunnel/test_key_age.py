"""Open issue 5: an optional limit on the age of the static key (0 = off, the default).

vpn_keygen.py --out writes the creation date to <key file>.created. The limit reads that date. A key
without a valid date is refused while a limit is set, so the limit cannot be bypassed by deleting the file.
"""
import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from unittest import mock

import vpn_keygen
from vpn_keyfiles import check_key_age, CREATED_SUFFIX


class KeyAgeTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ioessa-age-test-")
        self.key = os.path.join(self.dir, "k.key")
        open(self.key, "w").close()
        self.today = datetime.now(timezone.utc).date()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def sidecar(self, day):
        with open(self.key + CREATED_SUFFIX, "w", encoding="ascii") as f:
            f.write(day.isoformat() + "\n")

    def test_limit_off_accepts_anything(self):
        check_key_age(self.key, 0)                     # no sidecar at all, still fine
        check_key_age(None, 0)

    def test_fresh_key_is_accepted(self):
        self.sidecar(self.today - timedelta(days=10))
        check_key_age(self.key, 365)

    def test_old_key_is_refused_with_the_age_and_the_fix(self):
        self.sidecar(self.today - timedelta(days=400))
        with self.assertRaises(RuntimeError) as cm:
            check_key_age(self.key, 365)
        self.assertIn("400 days old", str(cm.exception))
        self.assertIn("vpn_keygen.py --out", str(cm.exception))

    def test_limit_boundary_is_accepted(self):
        self.sidecar(self.today - timedelta(days=365))
        check_key_age(self.key, 365)

    def test_missing_sidecar_is_refused_while_a_limit_is_set(self):
        with self.assertRaises(RuntimeError) as cm:
            check_key_age(self.key, 365)
        self.assertIn("no valid", str(cm.exception))

    def test_unreadable_sidecar_is_refused(self):
        with open(self.key + CREATED_SUFFIX, "w", encoding="ascii") as f:
            f.write("not a date\n")
        with self.assertRaises(RuntimeError):
            check_key_age(self.key, 365)

    def test_environment_key_cannot_be_aged_so_a_limit_refuses_it(self):
        with self.assertRaises(RuntimeError) as cm:
            check_key_age(None, 365)
        self.assertIn("--key-file", str(cm.exception))

    def test_keygen_writes_todays_date_next_to_the_key(self):
        out = os.path.join(self.dir, "new.key")
        with mock.patch.object(sys, "argv", ["vpn_keygen.py", "--out", out]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            vpn_keygen.main()
        with open(out + CREATED_SUFFIX, "r", encoding="ascii") as f:
            self.assertEqual(date.fromisoformat(f.read().strip()), self.today)
        check_key_age(out, 1)                          # created today, so one day is enough

    def test_keygen_refuses_to_overwrite_an_existing_sidecar(self):
        out = os.path.join(self.dir, "again.key")
        with open(out + CREATED_SUFFIX, "w", encoding="ascii") as f:
            f.write("2020-01-01\n")
        with mock.patch.object(sys, "argv", ["vpn_keygen.py", "--out", out]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                vpn_keygen.main()
        self.assertFalse(os.path.exists(out))                   # nothing was written


if __name__ == "__main__":
    unittest.main()
