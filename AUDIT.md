# Mandate security review

The table below records the security findings addressed in the fork. Numbers are stable references for this review. Multiple findings can share a commit, and some fixes span several commits. The count describes the scope of this review and carries no independent severity rating.

## Authorization and recovery limits

**Open implementation gap.** Signing and reviewer approval work offline. The running agent still lacks per-action mandate enforcement and an expiry-triggered read-only mode. A successful offline check applies to the record and time checked. [Authorization process](docs/AUTHORIZATION.md)

**Trust boundary.** An operator who controls the executable and its trusted keys can change both. A signature proves who controlled the signing key. Actual authority over a target requires independent confirmation from its owner.

**Prior disclosures.** A source patch cannot recall a copied session token, password, API key or CA private key. Revoke or rotate affected credentials. If a CA key was exposed, replace the CA and remove the old trust anchor from clients. Older databases, logs, backups and cached responses can retain private values after an upgrade.

## Findings and fixes

### Finding 17 severity estimate

**Severity remains unscored for the shipped console.** In the revision immediately before the fix, configuring an MCP endpoint required a valid console session. Login used a single administrator credential. The client sent configured headers to the original endpoint during normal operation. An attacker controlling that endpoint could already read those headers. Endpoint control alone therefore establishes no additional credential disclosure attributable to the flaw. [Route registration and authentication](https://github.com/mandate-sec/mandate/blob/8a8b20eba70007721f12ca8d6983cd8216b5c65d/server/server.go#L867) · [Login check](https://github.com/mandate-sec/mandate/blob/8a8b20eba70007721f12ca8d6983cd8216b5c65d/server/auth.go#L241) · [Affected client](https://github.com/mandate-sec/mandate/blob/8a8b20eba70007721f12ca8d6983cd8216b5c65d/mcphttp/client.go)

The fix prevents forwarding credentials to a second origin. Configuring that destination through the stock console requires administrator privileges. A score would require evidence of the additional access the recipient gains through the forwarding behavior.

### Finding register

| # | Affected behavior | Fix commits |
|---|---|---|
| 1 | First administrator setup could be claimed without installation-owner proof | [c6bcfae](https://github.com/mandate-sec/mandate/commit/c6bcfae0b0c728eb6597c310d66b716deb3cda87) |
| 2 | Password guesses and simultaneous expensive password checks lacked limits | [32042e6](https://github.com/mandate-sec/mandate/commit/32042e6964f14b5ebbed4c5e46cedbbd24a449ec) |
| 3 | Stream URLs could contain reusable session tokens | [4e9cf11](https://github.com/mandate-sec/mandate/commit/4e9cf110a02b7feea45901e699a1f3abd4368632) |
| 4 | Console sessions relied on legacy workspace-derived signing keys | [1b1b4eb](https://github.com/mandate-sec/mandate/commit/1b1b4ebdb796f749387385f9c5f6799f6b48864f) |
| 5 | Console password changes and offline administrator resets left earlier sessions usable | [bd74b63](https://github.com/mandate-sec/mandate/commit/bd74b63b4e8f7334902dd3e7fecb29444cb8d1c1), [offline reset fix](https://github.com/mandate-sec/mandate/commit/afec6cb) |
| 6 | Open event streams could outlive session expiry or revocation | [728c530](https://github.com/mandate-sec/mandate/commit/728c53031f6db6486a12c4c2561e1a6f38ecc3d4) |
| 7 | Traffic capture retained sensitive HTTP headers | [ba7eff9](https://github.com/mandate-sec/mandate/commit/ba7eff98b34d42b41719e32ab7ebfe214404313b) |
| 8 | Captured URLs retained credentials | [db6f7f2](https://github.com/mandate-sec/mandate/commit/db6f7f2f92a1b82c5d3dbfd2151db044eb59cb18) |
| 9 | Custom Python tools inherited secrets from the server environment | [ba7eff9](https://github.com/mandate-sec/mandate/commit/ba7eff98b34d42b41719e32ab7ebfe214404313b) |
| 10 | Administrator setup and password changes exposed raw database write errors | [c6bcfae](https://github.com/mandate-sec/mandate/commit/c6bcfae0b0c728eb6597c310d66b716deb3cda87) |
| 11 | Workspace file operations could reach outside the workspace | [fbe0e7d](https://github.com/mandate-sec/mandate/commit/fbe0e7d9e011f828e9f293111a42b93867f81fbe) |
| 12 | Console, proxy and development UI listened beyond loopback by default | [6ede008](https://github.com/mandate-sec/mandate/commit/6ede008c3c9667e2b2439a039f1fd835c2a44858) |
| 13 | Disabled updater paths could still modify local state | [e876649](https://github.com/mandate-sec/mandate/commit/e87664917c819420f39882b3643c2b06330bdeae) |
| 14 | Capture proxy accepted unverified upstream TLS certificates | [0b39411](https://github.com/mandate-sec/mandate/commit/0b39411d4e49d4e1b339fab5e16885a8576f7575) |
| 15 | Proxy traffic could silently bypass recording policy | [0b39411](https://github.com/mandate-sec/mandate/commit/0b39411d4e49d4e1b339fab5e16885a8576f7575) |
| 16 | Additional MCP, enrichment and Python HTTPS clients skipped certificate checks | [8a8b20e](https://github.com/mandate-sec/mandate/commit/8a8b20eba70007721f12ca8d6983cd8216b5c65d) |
| 17 | MCP redirects and message destinations could cross credential origins | [94c6f3d](https://github.com/mandate-sec/mandate/commit/94c6f3d842cf1da80aaa2de964503e3248b13a27) |
| 18 | MCP response parsing and event-stream handshakes lacked resource bounds | [2f8c9d8](https://github.com/mandate-sec/mandate/commit/2f8c9d8fd1de123a96942439c8b266d7105ea3e1) |
| 19 | Workspace browsing could expose the proxy CA signing key | [c613978](https://github.com/mandate-sec/mandate/commit/c6139784eccde827d151bce8852b97e2f40035e4) |
| 20 | Legacy capture and blob reads could escape the traffic storage directory | [06048a9](https://github.com/mandate-sec/mandate/commit/06048a9e78c29ee4156acf8dc37b68b52e6473c7) |
| 21 | Notification redirects allowed HTTPS delivery to downgrade to HTTP | [85f1a22](https://github.com/mandate-sec/mandate/commit/85f1a22f2bf704516ccc4d6dcd5ddb80c69c8f38) |
| 22 | Provider error text could expose private details in notification history | [d67c5e0](https://github.com/mandate-sec/mandate/commit/d67c5e0abf15c0f70d23bc396c4ea664e2b22744), [c62a8d8](https://github.com/mandate-sec/mandate/commit/c62a8d87d8c201d7d395649f1d42c4306900add5), [87cdea3](https://github.com/mandate-sec/mandate/commit/87cdea383eff1193c88f6a28dd08dee607670951) |
| 23 | Settings disclosed suffixes of notification credentials and model API keys | [b03dc46](https://github.com/mandate-sec/mandate/commit/b03dc46a6f9dfef0d121b37d67773d985ea2b698), [13654db](https://github.com/mandate-sec/mandate/commit/13654dbc025f7bda59bc231aaf12f8fc8f47d834) |
| 24 | Model settings could reuse a saved credential with a changed destination | [eea56c8](https://github.com/mandate-sec/mandate/commit/eea56c8a1c672172227d4c318ad61ac3ce858c17) |
| 25 | An invalid model-list proxy URL could silently send the request directly | [443b62b](https://github.com/mandate-sec/mandate/commit/443b62ba23dc95681883228fd208222d9a1a8c02) |
| 26 | An invalid offline mandate could inject control characters into terminal diagnostics | [8345215](https://github.com/mandate-sec/mandate/commit/834521518fcb2c1b23261dc269188a8ea1ebca5c) |
| 27 | Signing prompts could fall back to visibly echoed passphrase input | [c37a9e4](https://github.com/mandate-sec/mandate/commit/c37a9e4e8370f34eeddbcaa696cd6af795e3dbc7) |
| 28 | An offline reviewer grant could be reused for a differently named engagement with matching signer and scope | [7be31ea](https://github.com/mandate-sec/mandate/commit/7be31ead88f8c3d3fd4be03e659dc8843dccc0f1) |
| 29 | Global proxy validation errors and startup logs could disclose credentials embedded in a rejected proxy URL | [162d2d6](https://github.com/mandate-sec/mandate/commit/162d2d68f79d90b9fac623519270d0b6e2c2d2c6) |
| 30 | Database startup errors could expose passwords from malformed PostgreSQL connection strings or URL query parameters | [6e08d12](https://github.com/mandate-sec/mandate/commit/6e08d1220d4788a9c06124184304a6bd94198884) |
| 31 | Viewing Markdown findings, reports or transcripts could automatically contact an image host selected by the content author | [bfd6d01](https://github.com/mandate-sec/mandate/commit/bfd6d0198f3abd65ac0432352d4f3136e93e0712) |
| 32 | Findings CSV exports allowed untrusted text to be interpreted as spreadsheet formulas | [f9cd005](https://github.com/mandate-sec/mandate/commit/f9cd005598508ddb51ad080d6060af1c098352ca) |
| 33 | With a traversable workspace and a typical Unix umask, other local accounts could read stored capture bodies. New capture directories are private. On upgrade, restrict the dedicated traffic directory to mode 0700 before restarting capture. Windows access depends on directory ACLs. | [7f31561](https://github.com/mandate-sec/mandate/commit/7f31561bd60ccec0093f2974231ddfe145b28021) |
| 34 | Docker password recovery sourced a checkout’s `.env` as shell code on the operator’s host. A modified file could run with the operator’s privileges. | [b102218](https://github.com/mandate-sec/mandate/commit/b102218) |
| 35 | Local password recovery printed the full connection string, including any embedded database password, in its target confirmation. | [afec6cb](https://github.com/mandate-sec/mandate/commit/afec6cb) |
| 36 | Authenticated findings exports could return database and local filesystem diagnostics to the console. Export errors now use fixed messages with recovery guidance. | [Export handler](server/server.go), [API regression](server/finding_traffic_test.go) |

## Cross-fork report review

Public default-branch source inspected on 2026-11-22. The comparison covers the report code below. Findings are based on source inspection, and behavior in packaged releases and deployed instances remains unverified.

| Finding | FailSafe | BaaRai | RuoJi6 |
| --- | --- | --- | --- |
| 31. Markdown can automatically load remote images | [Default image rendering](https://github.com/failsafe-security/artex/blob/main/web/src/components/markdown.tsx) | [Default image rendering](https://github.com/BaaRai/ARTEX/blob/main/web/src/components/markdown.tsx) | [Custom image renderer still permits remote sources](https://github.com/RuoJi6/ARTEX/blob/main/web/src/components/markdown.tsx) |
| 32. Findings CSV can interpret text as formulas | [No formula guard in the exporter](https://github.com/failsafe-security/artex/blob/main/report/findings.go#L145) | [Formula guard covers common prefixes, with narrower coverage than Mandate](https://github.com/BaaRai/ARTEX/blob/main/report/findings.go#L233) | [No formula guard in the exporter](https://github.com/RuoJi6/ARTEX/blob/main/report/findings.go#L151) |
| Report bug. Unrecognized severity sorts alongside critical findings | [Present](https://github.com/failsafe-security/artex/blob/main/report/findings.go#L22) | [Present](https://github.com/BaaRai/ARTEX/blob/main/report/findings.go#L26) | [Present](https://github.com/RuoJi6/ARTEX/blob/main/report/findings.go#L22) |
| Export bug. Unsupported formats start a database lookup before returning an error | [Present](https://github.com/failsafe-security/artex/blob/main/server/server.go#L2106) | [Present](https://github.com/BaaRai/ARTEX/blob/main/server/server.go#L2416) | [Present](https://github.com/RuoJi6/ARTEX/blob/main/server/server.go#L2444) |
| 36. Findings exports can return internal diagnostics | [Present](https://github.com/failsafe-security/artex/blob/main/server/server.go#L2106) | [Present](https://github.com/BaaRai/ARTEX/blob/main/server/server.go#L2416) | [Present](https://github.com/RuoJi6/ARTEX/blob/main/server/server.go#L2444) |

Mandate sorts informational and unrecognized severities below low severity in Markdown and CSV. Its summary Markdown also includes those findings in its severity counts. Export format validation now runs before the database lookup, and only ZIP exports create a temporary staging directory.
