# Rule stability policy

vibeaudit's rule IDs are an interface: CI configurations, baselines, inline `vibeaudit: ignore[ID]`
comments, `disable` lists and SARIF dashboards all refer to them. This policy says what an ID promises.

## Rule IDs

- **An ID never changes meaning.** `BE001` is SQL injection and stays SQL injection. A rule may get more
  precise (fewer false positives) or find more cases of the same problem; it is never repurposed.
- **IDs are never reused.** A rule that is no longer useful is deprecated: it keeps its ID and its entry in
  [docs/RULES.md](docs/RULES.md), stops reporting, and its ID stays reserved for good.
- **Severities can change** between minor releases when the benchmark shows the default was wrong; the
  change is listed in the [CHANGELOG](CHANGELOG.md).

## Preview rules

A rule is in **preview** when it is new or when its measured precision is not good enough to fail a build.

- Preview findings are always reported, marked `(preview)` in the terminal and `"preview": true` in JSON.
- They do not count toward `--fail-on`, the score or the grade, unless you pass `--include-preview` (or set
  `include-preview = true` in the configuration).
- **Every new rule starts as preview** and stays in preview for at least one release.
- A rule leaves preview when its precision on the **held-out** split of the
  [benchmark](benchmark/README.md) is at least 90%, measured on at least 5 labelled findings. Held-out
  repositories are never used to tune a rule, so this number is not flattered by fixes made while looking
  at the findings. Precision on the tuned split and seeded recall are necessary but not enough. The
  release that promotes a rule says so in the CHANGELOG.
- A stable rule whose precision falls below 90% is moved back to preview with the measured reason in its
  `preview_reason`, until it is fixed. `vibeaudit rules --format json` and docs/RULES.md show the status and
  the reason of every rule.

### Severe preview rules still gate

A few preview rules cover bug classes where a missed finding costs far more than a false alarm: command
injection (BE002), dynamic code execution (BE003), unsafe deserialization (BE004), open redirect (BE008)
and cross-site scripting (FE001), and, while they are in preview, committed API keys (SEC001) and signing secrets (SEC004). One missed instance can mean remote code execution or account takeover,
while a false alarm costs a reviewer a few minutes and an inline `vibeaudit: ignore`. So these rules are
marked `gates_in_preview`:

- Their findings are still marked `(preview)` and still show their measured precision in docs/RULES.md.
- They **do** count toward `--fail-on`, the score and the grade by default.
- `--no-gate-severe-preview` (or `gate-severe-preview = false` in the configuration) leaves them out, like
  any other preview rule. `--include-preview` keeps counting every preview rule, these included.
- New rules never start with `gates_in_preview`; a rule gets it only by a decision recorded in the CHANGELOG.

### Demotions

A stable rule goes back to preview when its held-out precision falls below 90% on at least 5 findings, for
example after a new held-out repository is added. The reason is recorded on the rule and in the CHANGELOG; the
cause is fixed on tuned-split cases only, and the rule leaves preview again once it meets the bar.

| Rule | Release | Held-out | Cause | Gates in preview |
| --- | --- | --- | --- | --- |
| UI014 Image without width and height | 0.9.2 | 6/7 (85.7%) | an `<img>` sized by CSS classes | no; stable again at 9/10 (90.0%) held-out once two later held-out batches added 3 true positives (the cause was never tuned on, so the earlier 6/7 still counts) |
| AUTH001 State-changing endpoint without authentication | 0.9.2 | 14/16 (87.5%) | server actions guarded by `assertDevelopment()` | yes, while in preview (a decision recorded in the 0.9.2 CHANGELOG); stable again after the fix (14/14) |
| CFG002 Unpinned container base image | 0.11.0 | 5/6 (83.3%) | a Gitpod development workspace image | no |
| QA001 No automated tests | 0.11.0 | 6/8 (75.0%) | Java tests under src/test are not counted | no; fixed (tests in every language count); re-graduate on fresh held-out data, since 6/6 on the repositories that showed the cause is not independent evidence |
| QA007 Package imported but not declared as a dependency | 0.11.0 | 6/7 (85.7%) | an example script importing an unpublished client | no |
| DATA012 Foreign key without an index | 0.11.0 | 19/28 (67.9%) | MariaDB/MySQL migrations, where InnoDB indexes foreign keys itself | no |
| UI009 Data loaded without loading or error state | 0.11.0 | 4/5 (80.0%) | an effect that only fills a form field | no |
| SEC001 Hardcoded API key or access token | after 0.11.4 | 2/17 (11.8%) | test vectors of a secret-redaction library (atuin) | yes (secrets still gate) |
| SEC004 Hardcoded or default signing secret | after 0.11.4 | 0/34 | Rust test helpers named `session(...)` (atuin), a cookiecutter placeholder | yes (secrets still gate) |
| AUTH005 Supabase table without Row Level Security | after 0.11.4 | 0/29 | SQL migrations of a project that does not use Supabase (atuin) | no |
| DATA006 Timestamp without time zone | after 0.11.4 | 11/23 (47.8%) | MySQL, SQLite and H2 timestamp columns (atuin, realworld-springboot-java) | no |

These four were measured when 20 repositories joined the corpus (8 held out) and stable held-out precision fell
from 94.1% to 76.8%. Their causes are fixed separately, but because the causes were seen on held-out repositories,
those repositories are not re-scored to graduate them: each rule leaves preview only when a fresh held-out batch,
chosen and pinned before it is scanned, measures it at 90% or more on at least 5 findings.

### Go, Java/Kotlin, C#, Rust and PHP

Findings in these languages (other than SEC and DEP rules) are preview until a language, or a rule within it,
measures at 90% or more on at least 5 held-out findings. A fresh batch of 10 repositories, two per language, was
chosen and pinned before it was scanned (go-rest-api, gin-boilerplate, kotlin-spring-realworld,
spring-security-polls, VerticalSliceArchitecture, clean-architecture-manga, Pentaract, rustapi, filament-demo,
LinkAce). Held-out precision, excluding SEC and DEP rules and the four rules above on the repositories that showed
their causes:

| Language | Fresh batch | All held-out | Main causes |
| --- | --- | --- | --- |
| Go | 2/2 | 12/32 (37.5%) | AUTH002 on chi routes mounted inside an authenticated group; BE001 on prepared-statement arguments |
| Java/Kotlin | 2/6 (33.3%) | 7/16 (43.8%) | JAVA001 and AUTH001 miss a project's own auth annotation (`@ApiKeySecured`) and statically imported HTTP methods |
| C# | 3/6 (50.0%) | 3/8 (37.5%) | AUTH003 when the owner check is in the use case (`Find(accountId, userId)`), not the controller |
| Rust | 3/5 (60.0%) | 22/36 (61.1%) | AUTH001 on public sign-up routes and handlers resolved by path to another function; DATA001 |
| PHP | 3/24 (12.5%) | 66/106 (62.3%) | FE001 on `{!! !!}` output that the model already escapes (LinkAce: 0/19) |

Ruby (Rails) was added after this batch, with four tuned repositories (railsgoat, rails-realworld, lobsters,
theodinproject) and two held out, chosen and pinned before they were scanned (once-campfire, maybe). All
findings on the two held-out repositories measure 16 of 104; most false positives (58) are AUTH001 on controllers authenticated by
the app's `Authentication` concern (`before_action` inside `included do`, the Rails 8 generator's pattern), which
is not followed yet. Ruby stays preview.

That cause was then fixed from a tuned repository that uses the same pattern (writebook): `include` of a concern
adds its `included do` filters, and class macros such as `allow_unauthenticated_access only: ...` expand to the
`skip_before_action` they run. Because the cause was seen on once-campfire and maybe, those two are not re-scored
to graduate Ruby; Ruby leaves preview only on a fresh held-out batch, chosen and pinned before it is scanned.

No language clears the bar, so all five stay preview. One rule does: **PHP BE001 (SQL injection) measures 31/33
(93.9%) on held-out repositories and leaves preview** for PHP; it already gated as a severe rule. PHP DATA001
measures 6/6 but the rule itself is preview everywhere, so it does not change. Go and Java/Kotlin AUTH010 measure
4/4 and 3/3, below 5 findings each.

## What the benchmark guards

CI runs `python tools/benchmark.py check` on every push. It fails when, compared with
[benchmark/baseline.json](benchmark/baseline.json):

- a rule's precision on the labelled corpus drops (a new, unlabelled finding counts as a false positive
  until someone labels it),
- a finding labelled as a true positive is no longer reported, or
- a rule finds fewer of its seeded examples.

A deliberate change (a fixed false positive, a new true positive) is accepted by labelling the new findings
and recording a new baseline with `python tools/benchmark.py baseline`, in the same pull request.

## v1.0 readiness criteria and compatibility contract

vibeaudit remains in `0.x` until every item below holds simultaneously:

1. **Frozen stable interfaces**:
   - **CLI & exit codes**: documented subcommands, scan/fix/mcp flags, and exit codes (`0` clean, `1` gating findings or empty non-opt-out scan, `2` usage/config error).
   - **Report schema**: the JSON report conforms to `src/vibeaudit/data/report.schema.json` and SARIF output conforms to OASIS SARIF 2.1.0.
   - **Configuration & scoring**: `.vibeaudit.toml` keys in `config.KEYS`, existing rule IDs, and the default `diminishing-v2` score model (`linear-v1` preserved via `--score-model`).
2. **Quality & validation bar**:
   - Zero known unhandled crashes or hangs across the benchmark corpus, fuzzing, and adversarial security suite.
   - Parallel execution (`--jobs`) must never silently produce incomplete results or crash when sequential fallback is possible: worker failures log diagnostics, discard partial parallel results, and fall back to sequential execution.
   - Persistent cache hits must produce equivalent findings, routes, score, grade, and coverage to uncached scans, with size-bounded cache reads and corruption resilience.
   - `--no-config` must have a documented, tested isolation guarantee for every supported external scanner and report `partial` coverage whenever full isolation cannot be guaranteed:

     | Scanner | `--no-config` isolation mechanism | Partial fallback behavior |
     | --- | --- | --- |
     | `gitleaks` | Temporary default config (`useDefault = true`), empty `--gitleaks-ignore-path`, `--ignore-gitleaks-allow` | Marks `failed` if output unreadable |
     | `bandit` | Temporary empty `skips: []` config passed via `-c` | Marks `failed` if output unreadable |
     | `semgrep` | `--no-git-ignore` with isolated working directory; stages a clean shadow tree omitting `.semgrepignore`/`.semgrep*` when repo ignore files exist (up to staging budget) | Marks `coverage.external.semgrep.isolation = "partial"` and `coverage.overall_status = "partial"` if staging limit exceeded or staging fails |
     | `osv-scanner` | Temporary empty `osv-scanner.toml` passed via `--config` | Marks `failed` if output unreadable |

   - Every stable rule meets `>= 90%` held-out precision, independently validated by at least 2 external labellers (published with Cohen's kappa).
3. **Release & upgrade policy**:
   - Releases that modify scoring formulas, exit codes, or compatibility contracts go through at least one release candidate (`vX.Y.0rc1`) and list any behavior change at the top of `CHANGELOG.md`.
   - From `1.0.0` onward, any breaking change to a frozen interface requires at least one minor release carrying deprecation warnings followed by a major version bump.
