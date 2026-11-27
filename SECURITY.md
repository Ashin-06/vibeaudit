# Security policy

## Reporting a vulnerability in vibeaudit

Please report security problems in vibeaudit itself privately, not in a public issue:

- Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then
  **Report a vulnerability**.
- Include the version (`vibeaudit --version`), how to reproduce it (a minimal repository or file is ideal),
  and what an attacker could do.

You should get a first answer within 7 days. Once a fix is released, the advisory is published and you are
credited unless you prefer otherwise.

Examples of what counts:

- Code execution, file writes or network requests triggered by scanning a repository (vibeaudit treats the
  scanned code as untrusted input and must never execute it).
- A way for a scanned repository to hide findings from a reviewer who used `--no-config`.
- Secrets from the scanned project leaking into reports, caches or LLM requests (secrets are redacted before
  anything is sent to an LLM).
- Injection through the MCP server's tool arguments.

Not a vulnerability in vibeaudit: a finding it missed or a false alarm. Those are ordinary bugs; please open
an issue with a minimal example.

## Supported versions

Only the latest release receives security fixes.

## Threat model for scanning untrusted repositories

`vibeaudit` is designed to scan untrusted code safely without executing it.

| Threat vector | Mitigation |
| --- | --- |
| Malicious symlinks (escape / loops) | Resolved against repository root; escapes and loops skipped and recorded in `meta.coverage`. |
| Oversized files | Enforced `--max-file-size` cap (default 1 MB) before parsing; skipped files reported in `meta.coverage`. |
| Deeply nested AST / syntax trees | Explicit stack/recursion guards and per-file timeout (`--file-timeout`); falls back cleanly without crashing. |
| Hostile `.vibeaudit.toml` / external configs | Strict schema validation (unknown keys exit 2); project `disable` warns loudly on `stderr`; `--no-config` ignores repo config and isolates external scanners. |
| Malicious git history / huge diffs | `64 KB` chunk-bounded streaming (`--history`) with commit, line-byte, and total patch byte limits. |
| Pathological regex input (ReDoS) | Linear-time lexers and patterns checked against adversarial payloads in CI (`tests/security/`). |
| Malicious filenames (HTML/shell injection) | Never passed through shell (`shell=False`); escaped in HTML (`html.escape`) and JSON/SARIF reports. |
| Untrusted code execution via plugins | `--plugin` is strictly CLI/API opt-in; `.vibeaudit.toml` cannot register or import plugins. |
| Hostile URLs (`file://`, `ftp://`, SSRF schemes) | `validate_http_url()` enforces `https://` (`http://` allowed only for loopback LLM endpoints) before every `urlopen`. |
| Untrusted LLM responses | Strict JSON parsing, line-bounds verification, parse validation, and rejection of patches containing `REDACTED`. |
| Malicious archive / zip-bomb bundles | `bundle.import_bundle()` enforces member count, manifest size, per-entry size, total uncompressed size, compression ratio (`200:1`), SHA-256 integrity, and RSA-verified threat feed anti-rollback. |
| Symlink overwrite via autofix | `fix.plan_findings()`, `Plan.apply()`, and `verify_plan()` skip symlinks so `--apply` and `--verify` rollback never replace symlinks or overwrite symlink targets outside the repo. |
| Prompt-injected MCP path traversal | Set `VIBEAUDIT_MCP_ROOTS` (separated by `os.pathsep`, e.g. `:` or `;`) to restrict `vibeaudit mcp` tools (`scan_project`, `scan_file`, `audit_current_file`, `list_routes`, `auto_repair`, `simulate_migration`) strictly to resolved subpaths of allowed root directories. |

## Threat feed cryptography

The shipped `vibeaudit` package (`vibeaudit.feed`) contains PKCS#1 v1.5 RSA SHA-256 signature verification only; key generation and feed signing helpers live exclusively in maintainer scripts under `tools/`. Signatures expire after 30 days and enforce non-decreasing version numbers against the cached feed.

## Release rollback and PyPI yank procedure

If a released package or binary introduces a critical security regression or packaging defect:

1. **Yank the compromised version on PyPI**: do not delete unless legally required; mark the affected version yanked in the PyPI project management UI (`Manage -> Releases -> Options -> Yank`) with a clear explanation pointing to the safe version.
2. **Mark or update the GitHub Release**: edit the GitHub release title/notes for the affected tag to include a prominent `[YANKED / DO NOT USE]` warning and remediation instructions. Do not rewrite existing signed git tags in place.
3. **Publish an advisory**: file a GitHub Security Advisory under the **Security** tab documenting affected versions, impact, and patched release.
4. **Cut a clean patch release**: ship `vX.Y.(Z+1)` through the normal tagged CI + OIDC PyPI + Sigstore attestation pipeline, then verify with `gh attestation verify` and the post-publish `verify-pypi` workflow.

## What vibeaudit does with your code

See [docs/PRIVACY.md](docs/PRIVACY.md) for the complete privacy and data-handling policy. In summary:

- It reads files; it never runs the code it scans. Plugins (`--plugin`) are your own code and are loaded
  only when you pass them.
- With network access it sends package names and pinned versions to PyPI, npm, Pub, RubyGems, and OSV.dev;
  `--offline` turns that off. `vibeaudit update` downloads data files from this repository.
- With `--llm` it sends redacted code excerpts around findings to the provider you chose, never without
  explicit invocation. Run `--privacy-report` to preview exact line ranges and redactions first.
- The configuration and feedback files in a scanned repository can turn rules off. When you audit code you
  do not trust, use `--no-config`.
