# Mandate records

This offline utility signs and verifies engagement records. The server does not enforce these records. A valid signature authenticates a document under the selected public key. It does not establish ownership of a target.

Use Python 3.11 or later and install the pinned dependency from this directory with `python -m pip install -r requirements.txt`. Run the following commands from the same directory.

```text
python mandate.py keygen
python mandate.py create --engagement "Local review" --name "Lab owner" --email owner@example.org --targets localhost --checks web_scan --expires 2026-12-05
python mandate.py verify
python mandate.py renew --expires 2026-12-12
```

The default signing key is encrypted under a passphrase in ~/.mandate/keys/signer.pem. Verification uses signer.pub from the same directory. For independent verification, provision a trusted public key separately and pass its path with --trusted-key. Keep that file outside the writer's control. Signing and renewal require the encrypted private key. Never commit private keys or engagement files.

An expiry date without a time means midnight UTC at the beginning of that date. Timestamps may include an explicit offset. Signatures cover UTF-8 JSON with sorted keys at every level, compact separators, no ASCII escaping and the signature field omitted. Duplicate fields are rejected. The signed schema permits only an integer for concurrency and no floating-point fields.
