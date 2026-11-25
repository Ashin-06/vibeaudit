# vibeaudit for VS Code and Cursor

Shows vibeaudit findings as you edit (missing auth, injection, unsafe model output, secrets, missing
timeouts and token limits, ...) and offers one-click fixes where `vibeaudit fix` has a codemod.

This extension is a thin client: it starts `vibeaudit lsp`, the language server that ships with the
`vibeaudit` Python package. Install that first:

```bash
pip install vibeaudit==0.13.0
```

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `vibeaudit.serverCommand` | `vibeaudit` | The program to start. Use a Python interpreter with `serverArgs` `["-m", "vibeaudit", "lsp"]` if `vibeaudit` is not on the PATH. |
| `vibeaudit.serverArgs` | `["lsp"]` | Its arguments. |

Both settings are machine-scoped, and the extension does not run in untrusted workspaces: a cloned
repository cannot make it start a different program.

## What it does

- Diagnostics for every file in the workspace, also for unsaved changes, matching `vibeaudit scan`.
- Python, JavaScript/TypeScript (with Vue and Svelte), Go, Java/Kotlin, C#, Rust and PHP; the extension
  starts in any workspace with one of their project files. Needs VS Code 1.91 or later (or Cursor).
- Quick fixes for the findings `vibeaudit fix` can rewrite, and a "fix all" source action per file.
- The server reads the workspace and never writes files; the editor applies the edits you accept.

Once published, install it from the VS Code Marketplace or Open VSX (Cursor, VSCodium) by searching for
"vibeaudit". Until then, or for a specific build, install a `.vsix` file with **Extensions: Install from VSIX...**. Every CI run builds one as an artifact.
