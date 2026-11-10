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
- A rule leaves preview when its precision on the [benchmark](benchmark/README.md) is at least 90%,
  measured on at least 5 labelled real-world findings, or, when real projects give too few findings, when
  it has seeded cases and no labelled false positive. The release that promotes it says so in the
  CHANGELOG.
- A stable rule whose precision falls below 90% is moved back to preview with the measured reason in its
  `preview_reason`, until it is fixed. `vibeaudit rules --format json` and docs/RULES.md show the status and
  the reason of every rule.

## What the benchmark guards

CI runs `python tools/benchmark.py check` on every push. It fails when, compared with
[benchmark/baseline.json](benchmark/baseline.json):

- a rule's precision on the labelled corpus drops (a new, unlabelled finding counts as a false positive
  until someone labels it),
- a finding labelled as a true positive is no longer reported, or
- a rule finds fewer of its seeded examples.

A deliberate change (a fixed false positive, a new true positive) is accepted by labelling the new findings
and recording a new baseline with `python tools/benchmark.py baseline`, in the same pull request.
