# Publishing to PyPI (one-time setup)

vibeaudit is on PyPI (from 0.9.3). Releases are built, signed and attached to GitHub releases by
`.github/workflows/release.yml`, which then starts `.github/workflows/publish.yml` for the tag. That uploads the same
attested wheel and sdist to PyPI with trusted publishing (OpenID Connect, no API token stored anywhere). It does
nothing until the steps below are done; they need the owner's PyPI account and are already done for this
repository.

1. Check that the name is free: <https://pypi.org/project/vibeaudit/> should show "Not Found". If someone else holds
   it, pick another distribution name and change `name` in `pyproject.toml` first.
2. Sign in to PyPI (with two-factor authentication on) and open **Your account > Publishing > Add a new pending
   publisher**. Enter:
   - PyPI project name: `vibeaudit`
   - Owner: `Ashin-06`
   - Repository name: `vibeaudit`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. In the GitHub repository, open **Settings > Environments > New environment**, name it `pypi`, and add yourself
   as a required reviewer, so every upload waits for your approval.
4. Open **Settings > Secrets and variables > Actions > Variables** and add `PYPI_PUBLISH` with the value `true`.
5. Push a version tag as usual. When the release workflow has attached the signed files, it starts the publish
   workflow, which downloads the release's wheel and sdist, checks their build provenance with
   `gh attestation verify`, waits for your approval in the `pypi` environment if you set one, and uploads. To
   publish an existing release, run the publish workflow by hand with its tag.

Keep the trusted publisher's workflow name as `publish.yml`. The release workflow starts it with a
`workflow_dispatch` rather than calling it as a reusable workflow, because PyPI checks the top-level workflow
that requested the token.

To stop publishing, delete the `PYPI_PUBLISH` variable (or set it to anything else): runs are then skipped.

The README installs from PyPI (`pip install vibeaudit`). The VS Code extension's README can do the same (see #33).
