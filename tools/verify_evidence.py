#!/usr/bin/env python3
"""Verify a Mandate findings ZIP in place without opening or extracting reports."""

import argparse
from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
import re
import subprocess
import sys
from urllib.parse import urlsplit
import zipfile
import zlib


EVIDENCE_ENTRY = re.compile(r"evidence/([1-9][0-9]*)/([1-9][0-9]*)/(manifest\.json|(?:request|response)\.(?:bin|http))")
REPORT_ENTRY = re.compile(r"[^/\\:\x00-\x1f]+\.md")
BODY_HASH = re.compile(r"[0-9a-f]{64}")
CHUNK_SIZE = 1024 * 1024
MANIFEST_LIMIT = 32 * CHUNK_SIZE
SIGNATURE_NAMESPACE = "mandate-evidence"
# Match the fields Mandate masks at capture time. Older exports can still contain them.
SENSITIVE_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization",
    "referer", "location", "content-location", "link", "refresh", "x-original-url", "x-rewrite-url",
})


@dataclass
class SharingPreview:
    reports: int = 0
    body_bytes: int = 0
    masked_headers: Counter = field(default_factory=Counter)
    unmasked_headers: Counter = field(default_factory=Counter)
    masked_queries: int = 0
    urls_to_review: int = 0

    def count_headers(self, headers):
        # The first line is the HTTP status or request line. Header continuations
        # count as additional content in the preceding field, including in old exports.
        lines = headers.split("\n")[1:]
        for index, line in enumerate(lines):
            if line.startswith((" ", "\t")):
                continue
            name, colon, value = line.partition(":")
            name = name.strip().lower()
            if not colon or name not in SENSITIVE_HEADERS:
                continue
            continuation = index + 1 < len(lines) and lines[index + 1].startswith((" ", "\t"))
            is_masked = value.strip() == "[REDACTED]" and not continuation
            counts = self.masked_headers if is_masked else self.unmasked_headers
            counts[name] += 1

    def count_url(self, value):
        if not isinstance(value, str):
            self.urls_to_review += 1
            return
        try:
            parts = urlsplit(value)
        except ValueError:
            self.urls_to_review += 1
            return
        self.masked_queries += parts.query == "redacted"
        has_query_value = parts.query not in ("", "redacted")
        if parts.username is not None or parts.fragment or has_query_value:
            self.urls_to_review += 1

    def show(self):
        print(f"Sharing preview: {self.reports} Markdown report(s), {self.body_bytes} raw HTTP body bytes (before ZIP duplication).")
        for label, counts in (("Redaction markers", self.masked_headers), ("Headers to review", self.unmasked_headers)):
            summary = ", ".join(f"{name} ({count})" for name, count in sorted(counts.items()))
            print(f"{label}: {summary or 'none'}")
        print(f"URL query redaction markers: {self.masked_queries}. Capture URLs to review: {self.urls_to_review}.")
        print("Review report text, HTTP bodies, and any other sensitive fields before sharing.")


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("manifest contains duplicate fields")
        result[key] = value
    return result


def check_body(stream, size, digest):
    hashed = hashlib.sha256()
    count = 0
    while chunk := stream.read(CHUNK_SIZE):
        hashed.update(chunk)
        count += len(chunk)
    if count != size or hashed.hexdigest() != digest:
        raise ValueError("body size or SHA-256 does not match the manifest")


def check_binding(archive, finding_id, binding_id, files, preview):
    try:
        with archive.open(files["manifest.json"]) as stream:
            raw = stream.read(MANIFEST_LIMIT + 1)
        if len(raw) > MANIFEST_LIMIT:
            raise ValueError("manifest exceeds 32 MiB")
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
        if manifest["id"] != binding_id or manifest["finding_id"] != finding_id:
            raise ValueError("manifest IDs do not match its archive path")
        snapshot = manifest["snapshot"]
        if preview is not None:
            preview.count_url(snapshot.get("url", ""))
        for side, prefix in (("request", "req"), ("response", "resp")):
            size = snapshot[prefix + "_len"]
            digest = snapshot[prefix + "_hash"]
            if type(size) is not int or size < 0 or not BODY_HASH.fullmatch(digest):
                raise ValueError("invalid body size or SHA-256 in manifest")
            head = snapshot.get(prefix + "_head", "").rstrip("\r\n") + "\n\n"
            head_bytes = head.encode("utf-8")
            body_entry, message_entry = files[side + ".bin"], files[side + ".http"]
            if body_entry.file_size != size or message_entry.file_size != size + len(head_bytes):
                raise ValueError("body size does not match the manifest")
            with archive.open(body_entry) as stream:
                check_body(stream, size, digest)
            with archive.open(message_entry) as stream:
                if stream.read(len(head_bytes)) != head_bytes:
                    raise ValueError("HTTP headers do not match the manifest")
                check_body(stream, size, digest)
            if preview is not None:
                preview.body_bytes += size
                preview.count_headers(head)
    except (AttributeError, KeyError, RecursionError, TypeError) as error:
        raise ValueError("missing or malformed evidence files or metadata") from error


def verify_archive(file, preview=None):
    with zipfile.ZipFile(file) as archive:
        seen = set()
        bindings = {}
        for entry in archive.infolist():
            name = entry.filename
            if name != entry.orig_filename or name.casefold() in seen:
                raise ValueError("ambiguous or duplicate archive entry")
            seen.add(name.casefold())
            match = EVIDENCE_ENTRY.fullmatch(name)
            if match:
                finding_id, binding_id, kind = match.groups()
                bindings.setdefault((finding_id, binding_id), {})[kind] = entry
            elif REPORT_ENTRY.fullmatch(name):
                with archive.open(entry) as stream:
                    while stream.read(CHUNK_SIZE):
                        pass  # Check the ZIP CRC without parsing Markdown.
                if preview is not None:
                    preview.reports += 1
            else:
                raise ValueError("unexpected entry in findings ZIP")
        for (finding_id, binding_id), files in bindings.items():
            try:
                check_binding(archive, finding_id, binding_id, files, preview)
            except ValueError as error:
                raise ValueError(f"evidence {finding_id}/{binding_id}: {error}") from error
        return len(bindings)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="findings ZIP exported by Mandate")
    parser.add_argument("--signature", help="detached OpenSSH signature file")
    parser.add_argument("--allowed-signers", help="trusted OpenSSH allowed signers file")
    parser.add_argument("--signer", help="expected identity in the allowed signers file")
    parser.add_argument("--sharing-preview", action="store_true", help="summarize included evidence and recognized redactions")
    args = parser.parse_args()
    verify_signature = any((args.signature, args.allowed_signers, args.signer))
    if verify_signature and not all((args.signature, args.allowed_signers, args.signer)):
        parser.error("signature verification requires --signature, --allowed-signers, and --signer")

    preview = SharingPreview() if args.sharing_preview else None
    try:
        with open(args.archive, "rb") as file:
            if verify_signature:
                result = subprocess.run(
                    ["ssh-keygen", "-Y", "verify", "-f", args.allowed_signers,
                     "-I", args.signer, "-n", SIGNATURE_NAMESPACE, "-s", args.signature],
                    stdin=file, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                if result.returncode:
                    raise ValueError("signature verification failed")
                file.seek(0)
            count = verify_archive(file, preview)
    except (EOFError, OSError, RuntimeError, ValueError, zipfile.BadZipFile, zlib.error) as error:
        print(f"Verification failed: {str(error)!r}", file=sys.stderr)
        return 1

    print(f"Verified {count} evidence binding(s).")
    print("Trusted signature verified." if verify_signature else "Signer authenticity was not checked.")
    if preview is not None:
        preview.show()
    return 0


if __name__ == "__main__":
    sys.exit(main())
