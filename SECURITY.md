# Security policy

## Reporting a vulnerability

Open the [Security tab for mandate-sec/mandate](https://github.com/mandate-sec/mandate/security) and check for **Report a vulnerability**. If available, use that private form. Include the affected commit or release, the impact you observed, and a minimal example using synthetic data.

If the form is unavailable, ask the Mandate maintainer to enable private reporting or provide a verified private contact. Keep that request free of vulnerability details. Redact credentials, session tokens, private keys, and client traffic from any evidence you share.

For the historical upstream image investigation, see [the provenance notes](PROVENANCE.md) and [the source audit](audit/artex-v0.3.15-audit.md).

## Supported versions

Only the latest release built from this repository is supported. Upstream tags
that have not been reviewed and rebuilt here are not supported.

## Intended use

ARTEX is an autonomous security testing agent. It can execute shell commands,
run tools, and send arbitrary network traffic. It is intended only for systems
you own or have explicit written authorization to test. You are responsible for
scope, rules of engagement, and applicable law.

## Deployment guidance

- **Bind to localhost.** The default compose file publishes only
  `127.0.0.1:8787`. If you expose the console, put it behind an authenticated
  reverse proxy and TLS. Do not expose the recording proxy.
- **Use a fresh database and keys.** Do not reuse a database or `.env` from a
  host that ran a prebuilt ARTEX image.
- **Treat the console as admin-equivalent.** Custom Python tools and MCP stdio
  servers execute arbitrary code by design. A stolen admin session is code
  execution.
- **Keep the runtime unprivileged.** The application image uses UID and GID 10001. Compose drops all Linux capabilities and sets `no-new-privileges`. Keep the Docker socket outside the container.
- **Review skills.** `skills/` is copied into the image. A skill can instruct
  the agent to run commands. Review any skill you add or mount.
- **Keep secrets out of images.** The image contains no API keys, database
  passwords, or JWT keys. Pass them at runtime through `.env.safe`. The JWT
  signing key is generated on first boot and stored in the `artex_key` volume.
- **Limit egress.** The agent needs network access to the targets you
  authorize. Egress filtering is recommended for production use.

## Supply chain

- Base images are pinned by digest in `Dockerfile.safe`.
- The application is built from source in this repository; no prebuilt ARTEX
  image is pulled.
- Go module checksums are verified with `go mod verify`; there are no `replace`
  directives in `go.mod`.
- Node 22 is copied from the pinned `node:22-slim` stage. `@playwright/mcp`,
  `@playwright/cli`, and `playwright` are installed at pinned versions, and
  Chromium is installed with `playwright install --with-deps chromium`.
- Release artifacts should be published with SHA-256 checksums and, once
  available, a signed image and SBOM. Signing is not yet automated.

## Known residual risks

1. **Source provenance.** The `v0.3.15` source comes from a mirror of the
   original project because the original upstream is unavailable. The build is
   reproducible from this tree, but that proves the binary matches the tree,
   not that the tree matches the original author's last release.
2. **Dependency trust.** Third-party Go modules, apt packages, npm packages,
   and Chromium are verified by their ecosystems but not audited line by line.
   The browser stack is the largest third-party surface in the image.
3. **Runtime access.** Code running as the service account can access its workspace and session key. Keep backups outside the service account's control.
4. **No signature verification on self-update.** Online update checks and downloads are disabled
   by the compile-time `selfupdate.Enabled = false` constant. Do not re-enable it against an untrusted
   feed.
5. **Browser sandboxing.** Chromium runs with `--no-sandbox` for
   reliable startup, so the browser's own sandbox is not a security boundary
   here. Rely on the container and host isolation instead.