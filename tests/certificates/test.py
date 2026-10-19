#!/usr/bin/env python3
"""Reproduce Archive.org's redundant serial-zero root without the internet.

The server sends leaf -> cross-signed current root -> legacy root (serial 0).
The client already trusts the current root, as Mozilla's bundle does. wolfSSL
5.9.2 without WOLFSSL_ASN_ALLOW_0_SERIAL rejects the redundant legacy root
before it can build this shorter trusted path.
"""

import base64
import pathlib
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

CLIENT = str(pathlib.Path(sys.argv.pop(1)).resolve())
if not pathlib.Path(CLIENT).is_file():
    raise SystemExit("missing certificate test client: " + CLIENT)


class Certificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.path = pathlib.Path(cls.work.name)

        def openssl(*args):
            subprocess.run(
                ["openssl", *args],
                cwd=cls.path,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )

        cls.openssl = staticmethod(openssl)
        ca = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
        cls.path.joinpath("ca.ext").write_text(ca)
        cls.path.joinpath("leaf.ext").write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
        )
        cls.path.joinpath("wrong-san.ext").write_text(
            "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:other.example\n"
        )
        for name in ("legacy", "current", "other", "leaf"):
            openssl(
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                name + ".key",
                "-out",
                name + ".csr",
                "-subj",
                "/CN=" + ("localhost" if name == "leaf" else name),
            )
        for name, serial in (("legacy", "0"), ("current", "1"), ("other", "2")):
            openssl(
                "x509",
                "-req",
                "-in",
                name + ".csr",
                "-signkey",
                name + ".key",
                "-set_serial",
                serial,
                "-days",
                "2",
                "-extfile",
                "ca.ext",
                "-out",
                name + ".pem",
            )
        openssl(
            "x509",
            "-req",
            "-in",
            "legacy.csr",
            "-signkey",
            "legacy.key",
            "-set_serial",
            "3",
            "-days",
            "2",
            "-extfile",
            "ca.ext",
            "-out",
            "legacy-positive.pem",
        )
        openssl(
            "x509",
            "-req",
            "-in",
            "current.csr",
            "-CA",
            "legacy.pem",
            "-CAkey",
            "legacy.key",
            "-set_serial",
            "4",
            "-days",
            "2",
            "-extfile",
            "ca.ext",
            "-out",
            "cross.pem",
        )
        for name, ext in (("leaf", "leaf.ext"), ("wrong-san", "wrong-san.ext")):
            openssl(
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "current.pem",
                "-CAkey",
                "current.key",
                "-set_serial",
                "5",
                "-days",
                "2",
                "-extfile",
                ext,
                "-out",
                name + ".pem",
            )
        for name in ("leaf", "cross"):
            text = cls.path.joinpath(name + ".pem").read_text()
            der = bytearray(base64.b64decode("".join(text.splitlines()[1:-1])))
            der[-1] ^= 1  # Only the signature changes; structure and public key stay valid.
            encoded = base64.b64encode(der).decode()
            cls.path.joinpath(name + "-bad.pem").write_text(
                "-----BEGIN CERTIFICATE-----\n"
                + "\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))
                + "\n-----END CERTIFICATE-----\n"
            )
        openssl("x509", "-in", "legacy.pem", "-outform", "DER", "-out", "legacy.der")
        der = cls.path.joinpath("legacy.der").read_bytes()
        cls.path.joinpath("bad-tag.der").write_bytes(b"\x31" + der[1:])
        cls.path.joinpath("truncated.der").write_bytes(der[:-8])

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def connect(self, chain, trust="current", hostname="localhost", error=0):
        chain_path = self.path / "server-chain.pem"
        chain_path.write_text("".join((self.path / (name + ".pem")).read_text() for name in chain))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(chain_path, self.path / "leaf.key")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(8)
        port = listener.getsockname()[1]
        failures = []

        def serve():
            try:
                with listener:
                    raw, _ = listener.accept()
                    with raw:
                        raw.settimeout(5)
                        with ctx.wrap_socket(raw, server_side=True) as conn:
                            conn.recv(4096)
                            conn.sendall(
                                b"HTTP/1.0 200 OK\r\nContent-Length: 19\r\n\r\ncertificate fixture"
                            )
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                pass  # Expected when the client refuses a certificate.
            except Exception as exc:
                failures.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        run = subprocess.run(
            [CLIENT, str(self.path / (trust + ".pem")), str(port), hostname],
            text=True,
            capture_output=True,
            timeout=10,
        )
        thread.join(8)
        self.assertFalse(thread.is_alive(), "fixture server did not stop")
        self.assertFalse(failures, failures)
        self.assertEqual(run.returncode, 0 if error == 0 else 1, run.stdout + run.stderr)
        match = re.search(r"handshake error=(-?\d+)", run.stdout)
        self.assertIsNotNone(match, run.stdout + run.stderr)
        self.assertEqual(int(match[1]), error, run.stdout + run.stderr)

    def test_short_trusted_chain(self):
        self.connect(["leaf"])

    def test_positive_serial_full_chain(self):
        self.connect(["leaf", "cross", "legacy-positive"])

    def test_archive_chain_with_redundant_zero_serial_root(self):
        self.connect(["leaf", "cross", "legacy"])

    def test_zero_serial_root_as_explicit_trust_anchor(self):
        self.connect(["leaf", "cross", "legacy"], trust="legacy")

    def test_wrong_hostname_is_rejected(self):
        self.connect(["leaf", "cross", "legacy"], hostname="other.example", error=-322)

    def test_matching_cn_does_not_override_wrong_san(self):
        self.connect(["wrong-san", "cross", "legacy"], error=-322)

    def test_untrusted_zero_serial_chain_is_rejected(self):
        self.connect(["leaf", "cross", "legacy"], trust="other", error=-188)

    def test_untrusted_positive_serial_chain_is_rejected(self):
        self.connect(["leaf", "cross", "legacy-positive"], trust="other", error=-188)

    def test_forged_leaf_is_rejected(self):
        self.connect(["leaf-bad", "cross", "legacy"], error=-155)

    def test_forged_intermediate_is_rejected(self):
        self.connect(["leaf", "cross-bad", "legacy"], trust="legacy", error=-155)

    def parse(self, filename, expected):
        run = subprocess.run(
            [CLIENT, "--parse", str(self.path / filename)],
            text=True,
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(run.returncode, expected, run.stdout + run.stderr)

    def test_zero_serial_root_can_be_decoded(self):
        self.parse("legacy.der", 0)

    def test_malformed_asn1_tag_is_rejected(self):
        self.parse("bad-tag.der", 1)

    def test_truncated_asn1_is_rejected(self):
        self.parse("truncated.der", 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
