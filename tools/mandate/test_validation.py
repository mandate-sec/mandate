import tempfile
import unittest
from pathlib import Path

import mandate


class ValidationTests(unittest.TestCase):
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
