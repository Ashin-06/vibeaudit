// Thin VS Code / Cursor client: starts `vibeaudit lsp` and lets vscode-languageclient do the rest
// (diagnostics, quick fixes, "fix all"). All analysis happens in the Python language server.
"use strict";

const vscode = require("vscode");
const { LanguageClient, TransportKind } = require("vscode-languageclient/node");

let client;

function serverOptions() {
  const config = vscode.workspace.getConfiguration("vibeaudit");
  // machine-scoped settings: a cloned repository's .vscode/settings.json cannot change the program run here
  const command = config.get("serverCommand", "vibeaudit");
  const args = config.get("serverArgs", ["lsp"]);
  return { command, args, transport: TransportKind.stdio };
}

async function start(context) {
  const languages = ["python", "javascript", "javascriptreact", "typescript", "typescriptreact"];
  client = new LanguageClient(
    "vibeaudit",
    "vibeaudit",
    serverOptions(),
    { documentSelector: languages.map((language) => ({ scheme: "file", language })) }
  );
  try {
    await client.start();
  } catch (err) {
    vscode.window.showErrorMessage(
      "vibeaudit: could not start the language server (" + err.message + "). " +
      "Install it with `pip install vibeaudit` or set vibeaudit.serverCommand."
    );
  }
}

async function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand("vibeaudit.restart", async () => {
      if (client) {
        await client.stop();
      }
      await start(context);
    })
  );
  await start(context);
}

function deactivate() {
  return client ? client.stop() : undefined;
}

module.exports = { activate, deactivate };
