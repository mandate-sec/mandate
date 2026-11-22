#!/usr/bin/env python3
"""Verify a Mandate findings ZIP in place without opening or extracting reports."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import zipfile
import zlib


EVIDENCE_ENTRY = re.compile(r"evidence/([1-9][0-9]*)/([1-9][0-9]*)/(manifest\.json|(?:request|response)\.(?:bin|http))")
REPORT_ENTRY = re.compile(r"[^/\\:\x00-\x1f]+\.md")
BODY_HASH = re.compile(r"[0-9a-f]{64}")
CHUNK_SIZE = 1024 * 1024
MANIFEST_LIMIT = 32 * CHUNK_SIZE
SIGNATURE_NAMESPACE = "mandate-evidence"


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


def check_binding(archive, finding_id, binding_id, files):
    try:
        with archive.open(files["manifest.json"]) as stream:
            raw = stream.read(MANIFEST_LIMIT + 1)
        if len(raw) > MANIFEST_LIMIT:
            raise ValueError("manifest exceeds 32 MiB")
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
        if manifest["id"] != binding_id or manifest["finding_id"] != finding_id:
            raise ValueError("manifest IDs do not match its archive path")
        snapshot = manifest["snapshot"]
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
    except (AttributeError, KeyError, RecursionError, TypeError) as error:
        raise ValueError("missing or malformed evidence files or metadata") from error


def verify_archive(file):
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
            else:
                raise ValueError("unexpected entry in findings ZIP")
        for (finding_id, binding_id), files in bindings.items():
            try:
                check_binding(archive, finding_id, binding_id, files)
            except ValueError as error:
                raise ValueError(f"evidence {finding_id}/{binding_id}: {error}") from error
        return len(bindings)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="findings ZIP exported by Mandate")
    parser.add_argument("--signature", help="detached OpenSSH signature file")
    parser.add_argument("--allowed-signers", help="trusted OpenSSH allowed signers file")
    parser.add_argument("--signer", help="expected identity in the allowed signers file")
    args = parser.parse_args()
    verify_signature = any((args.signature, args.allowed_signers, args.signer))
    if verify_signature and not all((args.signature, args.allowed_signers, args.signer)):
        parser.error("signature verification requires --signature, --allowed-signers, and --signer")

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
            count = verify_archive(file)
    except (EOFError, OSError, RuntimeError, ValueError, zipfile.BadZipFile, zlib.error) as error:
        print(f"Verification failed: {str(error)!r}", file=sys.stderr)
        return 1

    print(f"Verified {count} evidence binding(s).")
    print("Trusted signature verified." if verify_signature else "Signer authenticity was not checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
