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

## What vibeaudit does with your code

- It reads files; it never runs the code it scans. Plugins (`--plugin`) are your own code and are loaded
  only when you pass them.
- With network access it sends package names and pinned versions to PyPI, npm and OSV.dev; `--offline`
  turns that off. `vibeaudit update` downloads data files from this repository.
- With `--llm` it sends code excerpts around findings to the provider you chose, with secrets redacted.
  Without `--llm` no code leaves your machine.
- The configuration and feedback files in a scanned repository can turn rules off. When you audit code you
  do not trust, use `--no-config`.
