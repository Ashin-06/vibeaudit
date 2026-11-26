# Changelog

The extension's version matches the vibeaudit release it is built with. What changed in the scanner and the
language server is in the project changelog:
https://github.com/Ashin-06/vibeaudit/blob/main/CHANGELOG.md

## 0.15.0

- Built with vibeaudit 0.15.0: adds Swift (iOS & Vapor) and Elixir (Phoenix) activation, XXE detection (`BE021`), multi-cloud GCP/Azure Terraform checks (`CFG020`), and `BE013`/`BE011` quick-fix codemods.

## 0.14.0

- Built with vibeaudit 0.14.0: adds LSP route hover (`auth_evidence`), feedback-driven rule demotion and helper suggestions, `vibeaudit init`, and optional `vibeaudit[parse]` tree-sitter support.

## 0.13.0

- Built with vibeaudit 0.13.0: adds MCP tool poisoning checks (`LLM027`/`LLM028`), Pub & RubyGems supply-chain checks, Firebase callable routes, mobile manifest TLS/debug checks, and `vibeaudit doctor`.

## 0.12.0

- Built with vibeaudit 0.12.0; adds Ruby (Rails) and Dart (Flutter) language activation.

## 0.11.4

- Built with vibeaudit 0.11.4.

## 0.11.3

- First release on the VS Code Marketplace and Open VSX.

## 0.11.2

- Covers Python, JavaScript/TypeScript (with Vue and Svelte), Go, Java/Kotlin, C#, Rust and PHP.
- Requires VS Code 1.91 or later (or Cursor).
- Shipped as a single bundled file.
