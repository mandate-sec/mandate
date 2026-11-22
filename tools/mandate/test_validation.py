import tempfile
import unittest
from pathlib import Path

import mandate


class ValidationTests(unittest.TestCase):
    def test_approval_network_containment(self):
        import json
        expires = "2030-01-01T00:00:00Z"
        grant = dict(key_fingerprint="test", targets=["192.0.2.0/28", "2001:db8::/64"],
                     checks=["web_scan"], max_concurrency=2, expires=expires)
        record = dict(authorized_by={"key_fingerprint": "test"}, constraints={"max_concurrency": 2},
                      scope={"checks": ["web_scan"]}, expires=expires)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "grant.json"
            path.write_text(json.dumps(grant))
            for value in ("192.0.2.0/28", "192.0.2.8/29", "192.0.2.15", "2001:db8::1"):
                record["scope"]["targets"] = [value]
                mandate.check_approval(record, path)
            for value in ("192.0.2.0/27", "192.0.2.16", "::ffff:192.0.2.1", "example.org"):
                record["scope"]["targets"] = ["192.0.2.1", value]
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "outside approval"):
                    mandate.check_approval(record, path)

    def test_reject_ambiguous_numeric_hosts(self):
        for value in ("127.1", "2130706433", "0x7f000001", "0127.0.0.1", "999.1.2.3", "fe80::1%eth0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mandate.target(value)
        for value in ("localhost", "127.0.0.1", "10.0.0.0/24", "::1", "42.example.org"):
            mandate.target(value)

    def test_reject_overflowing_offset(self):
        with self.assertRaises(ValueError):
            mandate.timestamp("2026-11-01T00:00:00+01:60")

    def test_oversized_record(self):
        with tempfile.TemporaryDirectory() as folder:
            key = mandate.Ed25519PrivateKey.generate()
            public = Path(folder) / "public"
            public.write_bytes(key.public_key().public_bytes(mandate.ser.Encoding.PEM,
                               mandate.ser.PublicFormat.SubjectPublicKeyInfo))
            record = Path(folder) / "record"
            record.write_bytes(b" " * (mandate.MAX_RECORD_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "size limit"):
                mandate.verify(record, public, None)
