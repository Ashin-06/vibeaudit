# The threat feed

vibeaudit's threat data lives in [`src/vibeaudit/data/threat_data.json`](../src/vibeaudit/data/threat_data.json):

| List | Used by | Entry |
| --- | --- | --- |
| `slopsquatted` | DEP001 | `ecosystem` (`PyPI` or `npm`), `name`, `note` (what it is and the real package), `source` |
| `model_sunsets` | LLM012 | `id`, `date` (retirement, `YYYY-MM-DD`), `replacement` (optional), `source` |
| `prompt_injection` | LLM019 | `id` (`PI` and a number), `pattern` (a Python regular expression), `description`, `source` |

The file ships with every release, so all three checks work offline. Between releases, a scheduled workflow
([`.github/workflows/feed.yml`](../.github/workflows/feed.yml)) signs the file as it is on `main` every day and
publishes it as `threat_feed.json` on the `threat-feed` branch. `vibeaudit update` downloads it, and scans add
its entries to the shipped ones.

## How a feed is checked

The signed file is `{"payload": "<JSON text>", "signature": "<base64>"}`. The payload holds the format, a
version (the signing time in seconds, which never decreases), the creation and expiry times (30 days after
signing) and the data. The signature is RSA PKCS#1 v1.5 with SHA-256 over the payload, made with a 3072-bit
key; vibeaudit verifies it with the standard library against the public key it ships
(`src/vibeaudit/data/feed_key.json`).

- `vibeaudit update` installs a downloaded feed only if the signature verifies, the contents are valid, it has
  not expired and it is not older than the installed one. Otherwise it keeps the current copy and says why.
- A scan uses the installed feed only if it still verifies and has not expired. Otherwise it prints a warning
  and uses the shipped data. With no installed feed it uses the shipped data silently.
- `vibeaudit update --export` puts the installed feed into the bundle and `--import` checks its signature
  before it writes anything, so an air-gapped machine trusts the feed the same way. The feed expires 30 days
  after signing, so an air-gapped machine needs a new bundle each month to keep it in use. After that it falls
  back to the shipped data, with a warning.

## Submitting an entry

Open a pull request that changes `src/vibeaudit/data/threat_data.json`. Every entry needs a `source`: a public
page that shows the claim.

- **Slopsquatted name**: a package name that models invent and that someone has registered. The source should
  show both: a write-up or report that models suggest the name, and the registration. Give the real package in
  `note`. Names that only look like typos of popular packages are already handled by DEP002.
- **Model sunset**: the provider's own deprecation page or announcement, with the retirement date it gives.
  Update the entry when the provider moves the date.
- **Prompt-injection pattern**: text that has been seen in agent instruction files (CLAUDE.md, AGENTS.md,
  .cursorrules, Copilot instructions and so on), from a published write-up. Keep the pattern narrow: it must
  not match ordinary instructions. The test suite compiles every pattern and checks that none matches
  vibeaudit's own documentation.

A maintainer checks the source before merging. Once the change is on `main`, the next daily feed carries it,
and the next release ships it.

## One-time setup (maintainer)

The repository secret holds the private key. The public key is committed. To set it up:

1. On your own machine, from the repository root, generate the key pair. The private key file must be outside
   the repository:

   ```bash
   python tools/gen_feed_key.py ~/vibeaudit-feed-key.json
   ```

   This writes the public key to `src/vibeaudit/data/feed_key.json`.
2. In the repository settings, under Environments, create an environment named `feed`. Under deployment
   branches, allow only `main`.
3. Add the private key as the environment secret `VIBEAUDIT_FEED_KEY`:

   ```bash
   gh secret set VIBEAUDIT_FEED_KEY --env feed < ~/vibeaudit-feed-key.json
   ```

   Then delete the file, or keep it somewhere offline if you want a backup.
4. Commit `src/vibeaudit/data/feed_key.json` in a pull request and merge it.
5. Run the "Threat feed" workflow once by hand (Actions, Threat feed, Run workflow) and check that the
   `threat-feed` branch has a `threat_feed.json`.

Releases made before step 4 have no public key. Their `vibeaudit update` says so and they use their shipped
data.

To rotate the key, run the script again with `--force`, replace the secret, and commit the new public key.
Installed copies with the old key reject the new feeds, with a warning, and use their shipped data until they
upgrade. If the private key leaks, rotate it at once and cut a release.
