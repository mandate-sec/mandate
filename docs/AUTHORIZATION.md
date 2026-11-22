# How authorization works

Mandate currently records approval offline. The signer issues a signed engagement document, and a reviewer verifies it against a public key they already trust. **The server does not consult this document before running tools. An expired or missing document does not put the console into read-only mode.**

## Who can approve an engagement?

The asset owner decides who may approve work for each asset. For a personal lab, the owner and operator can be the same person. For a client engagement, confirm the approver and their authority through an established client contact or written agreement. The name and email in the file are signed statements supplied by the signer. The CLI does not independently verify either one.

There is no central enrollment service. The reviewer chooses the trusted public key. Before accepting records from a new signer, obtain their public key and confirm its fingerprint through a separate trusted channel. The fingerprint printed by key generation is SHA-256 over the raw Ed25519 public key, encoded in base64 without padding. Store the approved public key somewhere the engagement author cannot overwrite. Accepting a public key solely because it arrived alongside a mandate would let anyone approve their own document.

## Issue, review, and renew

1. **Generate a key once.** From the [CLI directory](../tools/mandate/README.md), run `python mandate.py keygen`. The signer sets and confirms a passphrase of at least 12 characters. Keep the encrypted private key on the signing machine. Share only the public key and confirm its fingerprint.
2. **Issue a record.** Use `create` to specify the engagement, signer identity, targets, permitted checks, and expiry. The CLI prompts for the signing passphrase and creates `mandate.json`. The record also includes exclusions, concurrency, and constraints against denial of service and social engineering. Review those fields before handing it to an operator.
3. **Verify independently.** On the reviewing machine, use the public key you approved earlier. For example, run `python mandate.py verify --file engagement.json --trusted-key approved/lab-owner.pub`. The reviewer needs no passphrase or private key. A successful check prints the engagement and expiry. A rejected document returns a nonzero exit status.
4. **Compare the signed scope with the actual permission.** Check that the signer has authority over the listed assets and that the intended activity falls within the permitted targets, checks, exclusions, and time window. For example, a staging approver can produce a cryptographically valid signature over a document naming production. The current verifier cannot detect that the signer exceeded their authority.
5. **Renew or replace.** The signer can use `renew` with the matching private key and passphrase to extend the expiry, including after expiration. Renewal validates the original signature and preserves the scope. Issue a new document for a changed scope. A new document does not automatically invalidate earlier copies.

## What a successful verification establishes

The selected public key verifies the signature over the engagement fields, the key fingerprint matches, the record passes schema and constraint checks, and the verifier's clock falls within the validity window. The start is inclusive and the expiry is exclusive. A date-only expiry means the **start** of that date at midnight UTC. Changing a signed field invalidates the signature.

The CLI has no per-signer asset registry, revocation service, or runtime action gate. If a signing key is compromised, stop accepting its public key on each reviewing machine and distribute a newly approved key independently. Copies of the old record will still verify wherever the old key is trusted until they expire.
