# Publishing to PyPI (one-time setup)

vibeaudit is not on PyPI yet. Releases are built, signed and attached to GitHub releases by
`.github/workflows/release.yml`. `.github/workflows/publish.yml` can then upload the same attested wheel and sdist to
PyPI with trusted publishing (OpenID Connect, no API token stored anywhere). It does nothing until you do the
steps below, which need your own PyPI account.

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
5. Publish the next release as usual. The publish workflow downloads the release's wheel and sdist, checks their
   build provenance with `gh attestation verify`, waits for your approval in the `pypi` environment, and uploads.
   To publish an existing release, run the workflow by hand with its tag.

To stop publishing, delete the `PYPI_PUBLISH` variable (or set it to anything else): runs are then skipped.

After the first upload, the README's install line can become `pip install vibeaudit`, and the VS Code extension's
README can install from PyPI again (see #33).
