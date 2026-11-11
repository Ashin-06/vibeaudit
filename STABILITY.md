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
and cross-site scripting (FE001). One missed instance can mean remote code execution or account takeover,
while a false alarm costs a reviewer a few minutes and an inline `vibeaudit: ignore`. So these rules are
marked `gates_in_preview`:

- Their findings are still marked `(preview)` and still show their measured precision in docs/RULES.md.
- They **do** count toward `--fail-on`, the score and the grade by default.
- `--no-gate-severe-preview` (or `gate-severe-preview = false` in the configuration) leaves them out, like
  any other preview rule. `--include-preview` keeps counting every preview rule, these included.
- New rules never start with `gates_in_preview`; a rule gets it only by a decision recorded in the CHANGELOG.

## What the benchmark guards

CI runs `python tools/benchmark.py check` on every push. It fails when, compared with
[benchmark/baseline.json](benchmark/baseline.json):

- a rule's precision on the labelled corpus drops (a new, unlabelled finding counts as a false positive
  until someone labels it),
- a finding labelled as a true positive is no longer reported, or
- a rule finds fewer of its seeded examples.

A deliberate change (a fixed false positive, a new true positive) is accepted by labelling the new findings
and recording a new baseline with `python tools/benchmark.py baseline`, in the same pull request.
