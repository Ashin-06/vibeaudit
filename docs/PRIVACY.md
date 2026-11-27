# Privacy and Data-Handling Policy

This document describes what data `vibeaudit` reads, writes, caches, and transmits across every mode and integration.

## 1. Local-only default execution

- By default, `vibeaudit` never executes the code it scans and never transmits source files over the network.
- All static analyzers, route extraction, taint tracking, compliance mapping, HTML/SARIF/JSON report generation, deterministic codemods (`vibeaudit fix`), and signature verification of threat feeds execute locally on your machine.
- Telemetry and usage analytics do not exist: `vibeaudit` sends zero telemetry, crash reports, or anonymized statistics anywhere.

## 2. Offline guarantees (`--offline`)

- Running `vibeaudit scan . --offline` prevents all outbound network connections from the scanner (`deps`, update checks, and online OSV queries). A dedicated network-disabled test suite enforces this guarantee in CI.
- Air-gapped environments can build an offline bundle (`vibeaudit update --export bundle.zip --osv PyPI,npm`) on a connected host and import it on an offline host (`vibeaudit update --import bundle.zip`), after checking file hashes, size caps, compression ratios, and the threat feed signature.

## 3. Dependency and vulnerability lookups (online mode)

When scanning without `--offline`:

- **Sent**: declared package names and pinned versions parsed from lockfiles and manifests (such as `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`), plus local environment context for `osv-scanner` if enabled.
- **Not sent**: source code, file paths, secrets, environment files, or repository URLs.
- **Destinations (HTTPS only)**:
  - PyPI JSON API (`https://pypi.org/pypi/<name>/json`)
  - npm Registry (`https://registry.npmjs.org/<name>`)
  - Pub (`https://pub.dev/api/packages/<name>`) and RubyGems (`https://rubygems.org/api/v1/gems/<name>.json`)
  - OSV batch query API (`https://api.osv.dev/v1/querybatch`)

## 4. Optional LLM triage, review, and patch generation (`--llm`, `--llm-review`)

- `vibeaudit` never contacts an LLM provider unless you explicitly pass `--llm PROVIDER` (supported: `gemini`, `openai`, `openrouter`, `anthropic`) along with your own API key environment variable.
- Project `.vibeaudit.toml` files cannot force `watch`, `lsp`, `studio`, `mcp`, or the Python API to send code to an LLM.
- **Automatic redaction before transmission**: matched credentials, tokens, private keys, and `.env`-style secret values are replaced with `[REDACTED...]` markers via `llm.redact()` before prompt construction. Returned patches containing `REDACTED` are discarded.
- **Pre-flight inspection (`--privacy-report`)**: run `vibeaudit scan . --privacy-report [--llm-review]` to inspect the exact file names, line ranges, redacted byte counts, and number of redactions that would be transmitted, without making any network request or requiring an API key.

## 5. Threat-feed and popular-package updates (`vibeaudit update`)

- `vibeaudit update` fetches `top-pypi-packages.json.gz`, `npm-high-impact.json.gz`, `retired_models.json`, and the signed `threat_feed.json` from this repository over HTTPS.
- `threat_feed.json` is verified locally using RSA PKCS#1 v1.5 SHA-256 against the public key shipped with the package (`src/vibeaudit/data/feed_key.json`), plus 30-day expiry and anti-rollback version checks. The shipped package includes signature verification only (no private keys or signing logic).

## 6. Local cache and temporary files

- **Cache directory**:
  - Windows: `%LOCALAPPDATA%\vibeaudit`
  - macOS: `~/Library/Caches/vibeaudit`
  - Linux: `$XDG_CACHE_HOME/vibeaudit` or `~/.cache/vibeaudit`
  - Override with `VIBEAUDIT_CACHE_DIR`.
- **Cache contents & retention**: PyPI/npm metadata and OSV vulnerability answers cached for 24 hours ("package does not exist" for 1 hour; failed lookups never cached); LLM triage verdicts keyed by finding/snippet hash; imported threat feed and OSV indexes.
- **Disabling cache**: pass `--no-cache` or set `VIBEAUDIT_NO_CACHE=1`.
- **Temporary files**: created only inside OS-managed `tempfile.TemporaryDirectory()` blocks when invoking isolated external tools (`gitleaks`, `bandit`, `osv-scanner`) and cleaned up immediately upon completion.

## 7. Untrusted repositories (`--no-config`)

- Repositories can contain `.vibeaudit.toml`, `pyproject.toml`, `.vibeaudit/feedback.json`, or external scanner configs (`.bandit`, `.gitleaks.toml`, `.semgrepignore`, `osv-scanner.toml`).
- When auditing untrusted repositories, pass `--no-config`: `vibeaudit` ignores repository config and feedback files and isolates supported external scanners from repository ignore files.
- When repository config disables rules, `vibeaudit scan` warns on `stderr` and lists `meta.config_disabled` in reports.

## 8. Plugins (`--plugin`)

- Plugins execute user-supplied Python code and are **only** loaded when explicitly passed on the CLI (`--plugin`) or registered by the caller in Python. Repository `.vibeaudit.toml` files cannot load plugins.

## 9. Local UI, LSP, MCP, and Dynamic Probing

- `vibeaudit studio`: binds `127.0.0.1` only, uses zero external assets, validates `Host` headers against DNS rebinding, requires a per-session fragment token, and enforces a strict Content-Security-Policy.
- `vibeaudit mcp` / `vibeaudit lsp`: communicate over `stdio` only; restrict file reads to workspace-contained files. Set `VIBEAUDIT_MCP_ROOTS` (system path separator delimited) when running `vibeaudit mcp` to hard-confine all file/directory MCP tools to explicit root directories.
- `vibeaudit probe` / `vibeaudit test-exploit`: restricted to loopback targets (`127.0.0.1`, `::1`, `localhost`) by default and require explicit opt-in (`--i-own-this-target`) for non-local hosts; warn loudly when TLS verification is disabled.
