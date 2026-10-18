"""Open issue 15: optional HTTPS for the mock. Set VPN_TLS_CERT and VPN_TLS_KEY to turn it on.

The tests make a throwaway self-signed certificate in a temp directory. The key is never printed and
never kept after the tests.
"""
import datetime
import http.client
import ipaddress
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from test_web import ROOT, Server


def make_self_signed(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path


class HttpsTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="ioessa-tls-test-")
        cls.cert, cls.key = make_self_signed(cls.dir)
        cls.srv = Server(VPN_TLS_CERT=cls.cert, VPN_TLS_KEY=cls.key)

    @classmethod
    def tearDownClass(cls):
        cls.srv.proc.terminate()
        cls.srv.proc.wait(timeout=10)
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_https_serves_the_ui_with_hsts(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        ctx.check_hostname = False
        conn = http.client.HTTPSConnection("127.0.0.1", self.srv.port, context=ctx, timeout=10)
        conn.request("GET", "/")
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        self.assertIn("max-age=31536000", res.getheader("Strict-Transport-Security"))
        conn.close()

    def test_https_login_still_works(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        ctx.check_hostname = False
        conn = http.client.HTTPSConnection("127.0.0.1", self.srv.port, context=ctx, timeout=10)
        import json
        from test_web import PASSWORD
        conn.request("POST", "/api/login", json.dumps({"username": "demo", "password": PASSWORD}),
                     {"Content-Type": "application/json", "Host": f"127.0.0.1:{self.srv.port}"})
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        conn.close()

    def test_plain_http_is_not_answered_on_the_tls_port(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=10)
        try:
            conn.request("GET", "/")
            status = conn.getresponse().status
        except (http.client.HTTPException, OSError):
            status = None
        finally:
            conn.close()
        self.assertNotEqual(status, 200)


class TlsConfigTests(unittest.TestCase):

    def test_only_one_of_cert_and_key_stops_the_server(self):
        d = tempfile.mkdtemp(prefix="ioessa-tls-cfg-")
        try:
            cert, _ = make_self_signed(d)
            env = dict(os.environ, VPN_PORT="0", VPN_DEMO_PASSWORD="test-pass-for-unit-tests-1",
                       VPN_TLS_CERT=cert)
            env.pop("VPN_TLS_KEY", None)
            proc = subprocess.run([sys.executable, "server.py"], cwd=str(ROOT), env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("must be set together", proc.stderr + proc.stdout)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
