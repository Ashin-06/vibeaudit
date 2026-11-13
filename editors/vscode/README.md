# vibeaudit for VS Code and Cursor

Shows vibeaudit findings as you edit (missing auth, injection, unsafe model output, secrets, missing
timeouts and token limits, ...) and offers one-click fixes where `vibeaudit fix` has a codemod.

This extension is a thin client: it starts `vibeaudit lsp`, the language server that ships with the
`vibeaudit` Python package. Install that first:

```bash
pip install "vibeaudit @ git+https://github.com/Ashin-06/vibeaudit.git@v0.9.0"
```

vibeaudit is not published on PyPI: a package called `vibeaudit` there is not this project, so install from the
repository as above.

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `vibeaudit.serverCommand` | `vibeaudit` | The program to start. Use a Python interpreter with `serverArgs` `["-m", "vibeaudit", "lsp"]` if `vibeaudit` is not on the PATH. |
| `vibeaudit.serverArgs` | `["lsp"]` | Its arguments. |

Both settings are machine-scoped, and the extension does not run in untrusted workspaces: a cloned
repository cannot make it start a different program.

## What it does

- Diagnostics for every file in the workspace, also for unsaved changes, matching `vibeaudit scan`.
- Quick fixes for the findings `vibeaudit fix` can rewrite, and a "fix all" source action per file.
- The server reads the workspace and never writes files; the editor applies the edits you accept.

The extension is built in CI as a `.vsix` artifact and is not published to a marketplace. Install it with
**Extensions: Install from VSIX...**.
