"""Offline signed engagement records. No network access or agent integration."""
import argparse
import base64
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unicodedata
from datetime import date, datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEYS = Path.home() / ".mandate" / "keys"
MAX_RECORD_BYTES = 1024 * 1024
CHECKS = {"port_scan", "web_scan", "auth_bypass", "vuln_scan", "browser_capture"}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate field: " + key)
        obj[key] = value
    return obj


def exact(obj, fields):
    if not isinstance(obj, dict) or set(obj) != set(fields.split()):
        raise ValueError("expected fields: " + fields)


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", value):
        raise ValueError("expected RFC3339 timestamp with timezone")
    if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise ValueError("invalid timezone offset")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def expiry(value):
    if len(value) == 10:
        return date.fromisoformat(value).isoformat() + "T00:00:00Z"
    timestamp(value)
    return value


def target(value):
    if "%" in value:
        raise ValueError("scope identifiers are not allowed in addresses")
    try:
        ipaddress.ip_network(value, strict=True)
    except ValueError:
        if re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:\.(?:0[xX][0-9a-fA-F]+|[0-9]+))*", value):
            raise ValueError("ambiguous numeric address")
        if len(value) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in value.split(".")):
            raise ValueError("invalid hostname or network: " + value)


def validate(obj, now, allow_expired=False):
    exact(obj, "engagement authorized_by scope constraints valid_from expires")
    a, s, c = obj["authorized_by"], obj["scope"], obj["constraints"]
    exact(a, "name email key_fingerprint")
    exact(s, "targets checks excluded")
    exact(c, "no_dos no_social_engineering max_concurrency")
    if not all(isinstance(v, str) and v.strip() and not any(
        unicodedata.category(ch) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for ch in v
    ) for v in [obj["engagement"], *a.values()]):
        raise ValueError("missing engagement or signer identity")
    for k, items in s.items():
        if not isinstance(items, list) or any(not isinstance(v, str) or not v for v in items):
            raise ValueError("invalid " + k)
    if not s["targets"] or not s["checks"] or set(s["checks"]) - CHECKS:
        raise ValueError("empty scope or unknown check")
    for v in s["targets"] + [v for v in s["excluded"] if v not in CHECKS]:
        target(v)
    if c["no_dos"] is not True or c["no_social_engineering"] is not True or type(c["max_concurrency"]) is not int or not 1 <= c["max_concurrency"] <= 10:
        raise ValueError("invalid constraints")
    start, end = timestamp(obj["valid_from"]), timestamp(obj["expires"])
    if start >= end or now < start or (not allow_expired and now >= end):
        raise ValueError("mandate outside validity window")


def fingerprint(key):
    raw = key.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def write_new(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(data)


def signed(obj, key):
    signature = base64.b64encode(key.sign(canonical(obj))).decode()
    data = canonical(dict(obj, signature=signature)) + b"\n"
    if len(data) > MAX_RECORD_BYTES:
        raise ValueError("mandate exceeds size limit")
    return data


def verify(path, key_path, now, allow_expired=False):
    key = ser.load_pem_public_key(key_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected Ed25519 trusted key")
    with path.open("rb") as stream:
        raw = stream.read(MAX_RECORD_BYTES + 1)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("mandate exceeds size limit")
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    if not isinstance(obj, dict) or "signature" not in obj:
        raise ValueError("missing signature")
    sig = base64.b64decode(obj.pop("signature"), validate=True)
    key.verify(sig, canonical(obj))
    validate(obj, now, allow_expired)
    if obj["authorized_by"]["key_fingerprint"] != fingerprint(key):
        raise ValueError("signer fingerprint mismatch")
    return obj


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for cmd in ("keygen", "create", "verify", "renew"):
        p = sub.add_parser(cmd)
        if cmd != "verify":
            p.add_argument("--key", type=Path, default=KEYS / "signer.pem")
        p.add_argument("--trusted-key", type=Path, default=KEYS / "signer.pub")
        if cmd != "keygen":
            p.add_argument("--file", type=Path, default=Path("mandate.json"))
        if cmd in ("create", "renew"):
            p.add_argument("--expires", required=True)
        if cmd == "create":
            for field in ("engagement", "name", "email", "targets", "checks"):
                p.add_argument("--" + field, required=True)
            p.add_argument("--excluded", default="")
            p.add_argument("--max-concurrency", type=int, default=1)
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    if args.cmd == "keygen":
        if args.key.exists() or args.trusted_key.exists() or args.key.resolve() == args.trusted_key.resolve():
            raise ValueError("choose unused, distinct key paths")
        password = getpass.getpass("New signing passphrase: ")
        if len(password) < 12 or password != getpass.getpass("Confirm passphrase: "):
            raise ValueError("passphrases must match and contain at least 12 characters")
        key = Ed25519PrivateKey.generate()
        for path in (args.key, args.trusted_key):
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(args.key, key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(password.encode())))
        write_new(args.trusted_key, key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
        print(fingerprint(key.public_key()))
        return
    if args.cmd == "verify":
        obj = verify(args.file, args.trusted_key, now)
        print("Signature valid for the selected key:", obj["engagement"], "until", obj["expires"])
        return
    key = ser.load_pem_private_key(args.key.read_bytes(), getpass.getpass("Signing passphrase: ").encode())
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected encrypted Ed25519 key")
    fp = fingerprint(key.public_key())
    trusted = ser.load_pem_public_key(args.trusted_key.read_bytes())
    if not isinstance(trusted, Ed25519PublicKey) or fingerprint(trusted) != fp:
        raise ValueError("signing key does not match trusted key")
    if args.cmd == "renew":
        obj = verify(args.file, args.trusted_key, now, allow_expired=True)
        if timestamp(expiry(args.expires)) <= timestamp(obj["expires"]):
            raise ValueError("renewal must extend the expiry")
    else:
        obj = dict(engagement=args.engagement, authorized_by=dict(name=args.name, email=args.email, key_fingerprint=fp),
                   scope=dict(targets=args.targets.split(","), checks=args.checks.split(","), excluded=args.excluded.split(",") if args.excluded else []),
                   constraints=dict(no_dos=True, no_social_engineering=True, max_concurrency=args.max_concurrency),
                   valid_from=now.isoformat())
    obj["expires"] = expiry(args.expires)
    validate(obj, now)
    data = signed(obj, key)
    if args.cmd == "create":
        write_new(args.file, data)
    else:
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(dir=args.file.parent, delete=False) as f:
                tmp = Path(f.name)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            tmp.replace(args.file)
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
    print(args.file)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, RecursionError, InvalidSignature) as exc:
        sys.exit("Mandate rejected: " + (str(exc) or type(exc).__name__))
