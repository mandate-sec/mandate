import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

from tools import verify_evidence


PREFIX = "evidence/10/20/"


def fixture_entries():
    entries = {"10_high_example.md": b"# Example"}
    snapshot = {}
    for side, prefix, body in (("request", "req", b""), ("response", "resp", b"\x00\xff\r\n")):
        head = "Content-Type: application/octet-stream\r\n"
        snapshot.update({prefix + "_head": head, prefix + "_len": len(body),
                         prefix + "_hash": hashlib.sha256(body).hexdigest()})
        entries[PREFIX + side + ".bin"] = body
        entries[PREFIX + side + ".http"] = (head.rstrip("\r\n") + "\n\n").encode() + body
    entries[PREFIX + "manifest.json"] = json.dumps({"id": "20", "finding_id": "10", "snapshot": snapshot})
    return entries


def make_zip(entries):
    file = io.BytesIO()
    with zipfile.ZipFile(file, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return file


class VerifyEvidenceTests(unittest.TestCase):
    def test_valid_bundle_and_report_without_bindings(self):
        self.assertEqual(verify_evidence.verify_archive(make_zip(fixture_entries().items())), 1)
        self.assertEqual(verify_evidence.verify_archive(make_zip([("report.md", "# Report")])), 0)

    def test_rejects_tampered_body_and_http_copy(self):
        for name in ("response.bin", "response.http"):
            with self.subTest(name=name):
                entries = fixture_entries()
                path = PREFIX + name
                entries[path] = entries[path][:-1] + b"X"
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    verify_evidence.verify_archive(make_zip(entries.items()))

    def test_rejects_missing_attachment_and_duplicate_manifest_keys(self):
        entries = fixture_entries()
        del entries[PREFIX + "request.bin"]
        with self.assertRaisesRegex(ValueError, "missing or malformed"):
            verify_evidence.verify_archive(make_zip(entries.items()))
        entries = fixture_entries()
        manifest = PREFIX + "manifest.json"
        entries[manifest] = '{"id":"10",' + entries[manifest][1:]
        with self.assertRaisesRegex(ValueError, "duplicate fields"):
            verify_evidence.verify_archive(make_zip(entries.items()))

    def test_rejects_ambiguous_zip_entries(self):
        for name in ("report.md", "REPORT.md", "../report.md"):
            with self.subTest(name=name), warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with self.assertRaises(ValueError):
                    verify_evidence.verify_archive(make_zip([("report.md", "a"), (name, "b")]))

    def test_sharing_preview_shows_counts_without_exposing_values(self):
        entries = fixture_entries()
        manifest_path = PREFIX + "manifest.json"
        manifest = json.loads(entries[manifest_path])
        manifest["snapshot"]["url"] = "https://example.test/?token=fixture-query-value"
        head = (
            "GET / HTTP/1.1\r\n"
            "Authorization: [REDACTED]\r\n"
            "Cookie: [REDACTED]\r\n\tfixture-folded-value\r\n"
            "X-Api-Key: fixture-header-value"
        )
        manifest["snapshot"]["req_head"] = head
        entries[manifest_path] = json.dumps(manifest)
        entries[PREFIX + "request.http"] = (head + "\n\n").encode()

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "findings.zip"
            archive.write_bytes(make_zip(entries.items()).getvalue())
            result = subprocess.run(
                [sys.executable, verify_evidence.__file__, str(archive), "--sharing-preview"],
                check=True, capture_output=True, text=True,
            )
        self.assertIn("1 Markdown report(s), 4 raw HTTP body bytes", result.stdout)
        self.assertIn("Redaction markers: authorization (1)", result.stdout)
        self.assertIn("Headers to review: cookie (1), x-api-key (1)", result.stdout)
        self.assertIn("Capture URLs to review: 1", result.stdout)
        self.assertNotIn("fixture-", result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH is unavailable")
    def test_cli_checks_trusted_signature_and_detects_markdown_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key, archive = root / "signing_key", root / "findings.zip"
            signers = root / "allowed_signers"
            entries = fixture_entries()
            archive.write_bytes(make_zip(entries.items()).getvalue())
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                           check=True, capture_output=True)
            public_key = key.with_suffix(".pub").read_text(encoding="utf-8").split()[:2]
            signers.write_text("reviewer " + " ".join(public_key) + "\n", encoding="utf-8")
            subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n",
                            verify_evidence.SIGNATURE_NAMESPACE, str(archive)], check=True, capture_output=True)
            verify = [sys.executable, verify_evidence.__file__, str(archive), "--signature",
                      str(archive) + ".sig", "--allowed-signers", str(signers), "--signer", "reviewer"]
            result = subprocess.run(verify, check=True, capture_output=True, text=True)
            self.assertIn("Trusted signature verified", result.stdout)
            entries["10_high_example.md"] = b"# Changed"
            archive.write_bytes(make_zip(entries.items()).getvalue())
            result = subprocess.run(verify, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("signature verification failed", result.stderr)
