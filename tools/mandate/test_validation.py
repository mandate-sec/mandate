import tempfile
import unittest
import getpass
import os
import subprocess
import sys
from io import StringIO
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path

import mandate


class ValidationTests(unittest.TestCase):
    def test_network_masks_require_unambiguous_prefix_lengths(self):
        for value in ("0.0.0.0/0.0.0.0", "192.0.2.0/0.0.0.255", "192.0.2.0/255.255.255.0", "192.0.2.0/024"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "CIDR prefix"):
                mandate.target(value)
        for value in ("0.0.0.0/0", "192.0.2.0/24", "2001:db8::1/128"):
            mandate.target(value)

    def test_new_file_is_published_only_after_a_successful_write(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "record"
            with patch.object(os, "fsync", side_effect=OSError("flush failed")):
                with self.assertRaisesRegex(OSError, "flush failed"):
                    mandate.write_new(destination, b"first")
            self.assertEqual(list(Path(folder).iterdir()), [])
            mandate.write_new(destination, b"second")
            with self.assertRaises(FileExistsError):
                mandate.write_new(destination, b"third")
            self.assertEqual(destination.read_bytes(), b"second")
            self.assertEqual(list(Path(folder).iterdir()), [destination])

    def test_device_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "regular file"):
            mandate.read_key(Path(os.devnull))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires a POSIX FIFO")
    def test_fifo_without_writer_is_rejected_promptly(self):
        with tempfile.TemporaryDirectory() as folder:
            fifo = Path(folder) / "key"
            os.mkfifo(fifo)
            result = subprocess.run(
                [sys.executable, mandate.__file__, "verify", "--trusted-key", str(fifo)],
                capture_output=True, text=True, timeout=5,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected a regular file", result.stderr)

    def test_visible_passphrase_fallback_reads_nothing(self):
        source = StringIO("synthetic passphrase\n")
        with patch("sys.stdin", source), patch.object(getpass, "getpass", getpass.fallback_getpass):
            with self.assertRaisesRegex(ValueError, "hidden passphrase input"):
                mandate.signing_passphrase("Password: ")
        self.assertEqual(source.tell(), 0)

    def test_submicrosecond_validity_boundaries(self):
        record = dict(engagement="Local review", authorized_by=dict(name="Owner", email="owner@example.org", key_fingerprint="test"),
                      scope=dict(targets=["localhost"], checks=["web_scan"], excluded=[]),
                      constraints=dict(no_dos=True, no_social_engineering=True, max_concurrency=1),
                      valid_from="2030-01-01T00:00:00.0000001Z", expires="2030-01-01T00:00:00.0000011Z")
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, "validity window"):
            mandate.validate(record, now)
        mandate.validate(record, now.replace(microsecond=1))
        with self.assertRaisesRegex(ValueError, "validity window"):
            mandate.validate(record, now.replace(microsecond=2))
        self.assertEqual(mandate.timestamp(record["expires"]),
                         mandate.timestamp("2030-01-01T01:00:00.000001100+01:00"))

    def test_rejection_is_single_line_and_bounded(self):
        detail = "duplicate field: x\n\x1b[0m\u202ey" + "z" * 10000
        message = mandate.rejection_message(ValueError(detail))
        self.assertTrue(message.isprintable())
        self.assertIn(r"\x1b", message)
        self.assertLess(len(message), 300)

    def test_oversized_trusted_key(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "public"
            path.write_bytes(b"x" * (mandate.MAX_KEY_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "key file exceeds size limit"):
                mandate.verify(Path(folder) / "unused", path, None)

    def test_approval_network_containment(self):
        import json
        expires = "2030-01-01T00:00:00Z"
        grant = dict(engagement="Local review", key_fingerprint="test", targets=["192.0.2.0/28", "2001:db8::/64"],
                     checks=["web_scan"], max_concurrency=2, expires=expires)
        record = dict(engagement="Local review", authorized_by={"key_fingerprint": "test"}, constraints={"max_concurrency": 2},
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
