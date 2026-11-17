# Labelling findings independently

vibeaudit's precision numbers come from findings that the maintainers read in the code and labelled true or false.
To check those labels, we ask independent reviewers to label a blind sample, and we publish the agreement.

## What you get

`benchmark/second-label/sample.json`: about 150 findings drawn at random (fixed seed) from the labelled corpus,
stratified by rule category so every category is represented. Each item has the repository URL and pinned commit,
the file and line, the rule and its explanation. The maintainers' verdicts are not in it, and neither is any code:
the corpus is third-party code.

Check out the corpus with `python tools/benchmark.py fetch` (about 1.3 GB, outside this repository), then run
`python tools/labelling_kit.py show` to print each item with the code around it.

## How to label

For each item, answer `tp` (true positive) or `fp` (false positive). Open the file at the pinned commit when the
context is not enough. A finding is a true positive when:

- the code really has the problem the rule describes, at that location (a real risk or defect, not just a match);
- it would be worth telling the project's maintainers, even if the impact is small;
- a finding in test, example, seed or generated code is a false positive unless that code ships to production.

It is a false positive when the problem is not there (a sanitizer, a check elsewhere, a constant value, a
framework that handles it), or when the code never runs in production.

Do not look at the maintainers' labels (benchmark/labels/) until you have finished.

## Send your answers

Save a JSON object mapping each id to your verdict, for example `{"S001": "tp", "S002": "fp"}`, and open a pull
request adding it as `benchmark/second-label/answers-<your-name>.json`, or attach it to an issue.

`python tools/labelling_kit.py kappa answers.json` prints raw agreement and Cohen's kappa against the maintainers'
labels. Every set of answers we receive is published with its kappa, including the disagreements, and labels that
turn out to be wrong are corrected.
