# MCP server setup for coding agents

`vibeaudit mcp` runs a local, read-only [Model Context Protocol](https://modelcontextprotocol.io) server over
stdio so AI coding assistants can audit files they write, check dependencies before installing them, and
generate safe codemod diffs before handing code back to you.

Install `vibeaudit` first:

```bash
pip install vibeaudit
```

Or generate starter configs in one command with `vibeaudit init`:

```bash
vibeaudit init --mcp --agent-hooks
```

That writes `.mcp.json` (plus `.cursor/mcp.json` / `.vscode/mcp.json` if those folders exist) and a starter
`.claude/settings.json` `PostToolUse` hook that audits written or edited files automatically.

## Client setup

### Claude Code

Add vibeaudit for your workspace or user profile via CLI:

```bash
claude mcp add vibeaudit -- vibeaudit mcp
```

Or commit `.mcp.json` at the root of your repository so teammates get it automatically:

```json
{
  "mcpServers": {
    "vibeaudit": {
      "command": "vibeaudit",
      "args": ["mcp"]
    }
  }
}
```

### Cursor

Add `.cursor/mcp.json` in your repository (or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "vibeaudit": {
      "command": "vibeaudit",
      "args": ["mcp"]
    }
  }
}
```

### VS Code and GitHub Copilot

Add `.vscode/mcp.json` to your workspace:

```json
{
  "servers": {
    "vibeaudit": {
      "type": "stdio",
      "command": "vibeaudit",
      "args": ["mcp"]
    }
  }
}
```

## Prompt instruction for agents

Paste the snippet below into `CLAUDE.md`, `.cursor/rules`, or `.github/copilot-instructions.md` so the agent
checks its own changes automatically before finishing:

```markdown
## Security checks before finishing

- Before adding any new PyPI, npm, RubyGems, or Pub dependency, call vibeaudit `verify_package` to catch
  hallucinated package names, typosquats, brand-new packages, or known CVEs.
- Before saying you are done after editing backend, auth, config, database, or AI code, call vibeaudit
  `audit_current_file` (or `scan_project` with `changes: "staged"`) and fix any critical/high findings.
```

## Confining workspace access and auditing tool calls

When a client sends `rootUri`, `workspaceFolders`, or `roots` during `initialize`, `vibeaudit mcp`
automatically confines file and directory tools (`scan_project`, `scan_file`, `audit_current_file`,
`list_routes`, `auto_repair`, `verify_package`, `simulate_migration`) to those resolved workspace directories.
Set `VIBEAUDIT_MCP_ROOTS` using your OS path separator (`:` on Linux/macOS, `;` on Windows) to enforce an
explicit override, and set `VIBEAUDIT_MCP_AUDIT=1` to log tool-call telemetry JSON lines to `stderr`:

```json
{
  "mcpServers": {
    "vibeaudit": {
      "command": "vibeaudit",
      "args": ["mcp"],
      "env": {
        "VIBEAUDIT_MCP_ROOTS": "/path/to/workspace",
        "VIBEAUDIT_MCP_AUDIT": "1"
      }
    }
  }
}
```

## Checking third-party MCP servers before trusting them

Before enabling an external stdio MCP server in your editor, inspect its live `tools/list` output (read-only,
never invoking any tool) for hidden prompt-injection instructions, stealth Unicode, exfiltration parameters,
unconstrained shell tools, or definition changes (rug-pull drift):

```bash
vibeaudit probe --mcp-cmd "npx -y @example/mcp-server" --format json
vibeaudit probe --mcp-cmd "python server.py" --pin-hash <manifest_sha256>
```

## Available read-only tools

| Tool | Purpose |
| --- | --- |
| `scan_project` | Audit a directory (optionally only changed lines: `changes: "staged"` or a git revision). |
| `scan_file` | Audit one file in the context of its project. |
| `audit_current_file` | Audit unsaved or newly edited file content; reuses unchanged files across calls. |
| `list_routes` | Inventory HTTP/RPC routes with auth, data-write, and AI-call status. |
| `check_package` | Check whether a package exists, its release age, typosquat matches, and OSV advisories. |
| `verify_package` | `check_package` plus allow/caution/block verdict and import-to-package mapping (`cv2` -> `opencv-python`). |
| `simulate_migration` | Dry-run PostgreSQL DDL locks, table rewrites, and data-loss risks. |
| `explain_rule` | Return the rationale and remediation for any rule ID. |
| `auto_repair` | Return `vibeaudit fix` diffs without writing files. |
| `doctor` | Check installed parsers, threat-feed status, and offline OSV indexes. |
