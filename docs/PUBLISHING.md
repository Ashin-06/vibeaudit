# Publishing to PyPI (maintainer notes)

vibeaudit is on PyPI (from 0.9.3). Releases are built, signed and attached to GitHub releases by
`.github/workflows/release.yml`, which then starts `.github/workflows/publish.yml` for the tag. That uploads the same
attested wheel and sdist to PyPI with trusted publishing (OpenID Connect, no API token stored anywhere).

## One-time setup (done)

These steps need the owner's PyPI account. They are done for this repository and are kept here for reference.

1. Check that the name is free on <https://pypi.org/project/vibeaudit/>.
2. Sign in to PyPI (with two-factor authentication on) and open **Your account > Publishing > Add a new pending
   publisher**. Enter:
   - PyPI project name: `vibeaudit`
   - Owner: `Ashin-06`
   - Repository name: `vibeaudit`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. In the GitHub repository, open **Settings > Environments > New environment** and name it `pypi`. A required
   reviewer there makes every upload wait for approval.
4. Open **Settings > Secrets and variables > Actions > Variables** and add `PYPI_PUBLISH` with the value `true`.

## Each release

Push a version tag. When the release workflow has attached the signed files, it starts the publish workflow, which
downloads the release's wheel and sdist, checks their build provenance with `gh attestation verify`, waits for
approval in the `pypi` environment if a reviewer is set, and uploads. To publish an existing release, run the publish
workflow by hand with its tag.

Keep the trusted publisher's workflow name as `publish.yml`. The release workflow starts it with a
`workflow_dispatch` rather than calling it as a reusable workflow, because PyPI checks the top-level workflow that
requested the token.

To stop publishing, delete the `PYPI_PUBLISH` variable (or set it to anything else): runs are then skipped.


## VS Code extension (VS Code Marketplace and Open VSX)

`release.yml` publishes `editors/vscode` on every release once this one-time setup is done. Cursor and
VSCodium install from Open VSX, VS Code from the Marketplace; each is optional.

1. **Publisher.** Create a publisher at https://marketplace.visualstudio.com/manage and set `"publisher"` in
   `editors/vscode/package.json` to its ID (the same namespace is used on Open VSX).
2. **VS Code Marketplace token.** In Azure DevOps (https://dev.azure.com), create a personal access token with
   organization "All accessible organizations" and scope **Marketplace > Manage**.
3. **Open VSX token.** Sign in at https://open-vsx.org with GitHub, sign the publisher agreement, create an
   access token, and create the namespace once: `npx ovsx create-namespace <publisher> -p <token>`.
4. **GitHub.** Create the environment `vscode-marketplace` (Settings > Environments; allow only `main` and
   `v*` tags), add the secrets `VSCE_PAT` and `OVSX_PAT` to it, and set the repository variable
   `VSCODE_PUBLISH` to `true`.

The next tag then publishes the extension with the same version as the Python package. To publish an
existing release by hand: `cd editors/vscode && npm ci && npx vsce publish -p <VSCE_PAT>`.
