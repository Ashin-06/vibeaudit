# vibeaudit accuracy benchmark

This folder measures how often each rule is right. Results: [RESULTS.md](RESULTS.md) (generated, with the
table per rule) and [results.json](results.json). The policy that uses them: [STABILITY.md](../STABILITY.md).

## What is here

| Path | What it is |
| --- | --- |
| `corpus.json` | 32 public repositories, each pinned to an exact commit, with its licence and kind. |
| `labels/<repo>.json` | One entry per reviewed finding: rule, file, line, fingerprint, `tp` or `fp`, and a one-line reason. |
| `seeded/` | Small known-vulnerable apps with `expect: RULE` markers, for rules that real projects rarely trigger. |
| `baseline.json` | Per-rule precision and seeded recall (and per-repository counts) that the CI gate compares against. |
| `results.json`, `RESULTS.md` | The full results of the last `baseline` run. |

No code from the corpus is stored here: repositories are cloned at their pinned commit into
`$VIBEAUDIT_BENCH_DIR` (default `~/.cache/vibeaudit-bench`). Labels hold paths, line numbers, fingerprints
and our own one-line reasons, never secret values; several corpus repositories contain real-looking
credentials, which the review tooling masks. Repositories marked "none declared" have no licence file; we
only clone them for analysis and redistribute nothing from them.

## Corpus

Chosen to cover what vibeaudit is for and to keep it honest on code written by people who know what they
are doing:

- **ai-built (8):** apps generated with Lovable (found by the `lovable-tagger` dev dependency) that have
  Supabase edge functions, and other AI-assisted apps.
- **llm-app (8):** open-source chat, RAG and agent apps.
- **well-maintained (15):** frameworks, official templates and tutorials in Python and JavaScript/TypeScript.
  Almost everything reported here should be a false positive or a deliberate trade-off, so these keep the
  noise visible.
- **known-vulnerable (1):** a deliberately vulnerable Flask app.

| Repository | Kind | Source | Commit | Licence |
| --- | --- | --- | --- | --- |
| act-solo-ai | ai-built | afllewellyn/act-solo-ai | f4c6a6296c90 | none declared |
| helpdesk-flow-verse | ai-built | piyushraj04/helpdesk-flow-verse | c08ede8e4213 | none declared |
| learnathon-leaderboard | ai-built | BrainStation-23/learnathon-leaderboard | 87ee5a2d7c22 | none declared |
| LinguaLearn | ai-built | josephkamau32/LinguaLearn | f1cc2e2ea82e | none declared |
| physicalmediavault | ai-built | thamarakandabada/physicalmediavault | c411c1698cf6 | MIT |
| prompt-sculptor-49 | ai-built | amo-tech-ai/prompt-sculptor-49 | d60d5e9e66c6 | none declared |
| scriptforge-ai | ai-built | 3h0ll7/scriptforge-ai | 07f5342b53db | none declared |
| sync-plan-flow | ai-built | thefixer3x/sync-plan-flow | 9bbf2bf4b86d | none declared |
| ai-chatbot | llm-app | vercel/ai-chatbot | a8989b522fa3 | custom (see repository) |
| chat-langchain | llm-app | langchain-ai/chat-langchain | 1a5fbe967b47 | MIT |
| chatbot-ui | llm-app | mckaywrigley/chatbot-ui | 81328b61d2a4 | MIT |
| chatgpt-your-files | llm-app | supabase-community/chatgpt-your-files | 005fd90817fa | none declared |
| llm-examples | llm-app | streamlit/llm-examples | 7cf260745675 | Apache-2.0 |
| opengpts | llm-app | langchain-ai/opengpts | 8e7fef72e1f7 | MIT |
| openui | llm-app | wandb/openui | 42d7ab4ab665 | Apache-2.0 |
| sec-insights | llm-app | run-llama/sec-insights | a9b6da0f5c4b | MIT |
| bakerydemo | well-maintained | wagtail/bakerydemo | 890285b95dcf | BSD-3-Clause |
| commerce | well-maintained | vercel/commerce | f7521d57d29f | MIT |
| Django-Styleguide-Example | well-maintained | HackSoftware/Django-Styleguide-Example | a70ef43d7df0 | MIT |
| djangoproject.com | well-maintained | django/djangoproject.com | 83a027bb6aac | BSD-3-Clause |
| express | well-maintained | expressjs/express | 43fca52d28a4 | MIT |
| flask | well-maintained | pallets/flask | 49943b5a9441 | BSD-3-Clause |
| full-stack-fastapi-template | well-maintained | fastapi/full-stack-fastapi-template | aabb90126964 | MIT |
| microblog | well-maintained | miguelgrinberg/microblog | a975ef648643 | MIT |
| next-learn | well-maintained | vercel/next-learn | bb2558441a66 | MIT |
| nextjs-subscription-payments | well-maintained | vercel/nextjs-subscription-payments | bdd0813206e4 | MIT |
| node-express-boilerplate | well-maintained | hagopj13/node-express-boilerplate | 179ae84efec6 | MIT |
| node-express-realworld-example-app | well-maintained | gothinkster/node-express-realworld-example-app | 30b68e1e8814 | none declared |
| starlette | well-maintained | encode/starlette | 271c277da0ff | BSD-3-Clause |
| taxonomy | well-maintained | shadcn-ui/taxonomy | 298a8857c712 | MIT |
| werkzeug | well-maintained | pallets/werkzeug | 0f43c6ebd426 | BSD-3-Clause |
| Vulnerable-Flask-App | known-vulnerable | we45/Vulnerable-Flask-App | b6a4f97afd46 | none declared |

## How findings are labelled

Every finding was read in the code around it (and in the helpers, settings and config files it depends on)
before it got a verdict. A finding without a label is "needs review": it never counts as a true positive,
and the CI gate counts it as a false positive until someone labels it.

- **tp**: the rule's claim holds at that line, and a reviewer should look at it. A deliberate trade-off that
  the rule describes correctly (a dev image running as root, a default password in docker-compose) is a tp.
- **fp**: the claim is wrong in context. Examples: the auth check is in an imported helper; the value is
  staff-authored CMS HTML; the "secret" is a public client key; the query loop is in a one-off migration;
  CORS is open but no credentials are sent, so no one can act as the logged-in user.
- Rule-specific readings: DATA007 (env var missing from the example file) is a tp when a missing value
  crashes the app or silently switches a feature off, and an fp when the code has a default or the setting
  is optional by design. FE001 is a tp for `innerHTML` on a detached element (an `<img onerror>` still
  runs).
- Rules whose results depend on the network (DEP001, DEP003, DEP004) are excluded from the corpus scan;
  the online test suite covers them.

## Reproduce

```bash
python tools/benchmark.py fetch                 # clone every pinned commit into the cache (retried)
python tools/benchmark.py run --json out.json   # scan, compare with the labels, print the table
python tools/benchmark.py check                 # the CI gate
python tools/benchmark.py review NAME           # list unlabelled findings of one repository
python tools/benchmark.py baseline              # after labelling: record baseline, results.json, RESULTS.md
```

Seeded recall runs over `tests/fixtures` and `benchmark/seeded`; fake credentials are generated at run time,
so nothing credential-shaped is committed.

## Phase 0 results (0.6.0)

The first full run on 0.5.2 found 818 findings: 460 true and 358 false, 56% precision. Fixing the causes
of the false positives brought it to 524 findings, 461 true and 63 false (88%), with no true positive lost
(one new true positive appeared). Every fix has a regression test in `tests/test_benchmark_fixes.py` that
fails on 0.5.2.

Rules that were under 90% and what was done:

| Rule | Before | After | Decision |
| --- | --- | --- | --- |
| QA003 Exception silently swallowed | 2/62 (3%) | 2/6 (33%) | Fixed: specific exceptions (KeyError, OSError) and a comment above `pass` are deliberate; vendored bundles skipped. **Preview**: broad `except` in library cleanup code is often deliberate. |
| DATA001 Query inside a loop | 1/38 (3%) | 1/5 (20%) | Fixed: Django `tests.py`, library `examples/`, migrations, management commands and seed scripts. **Preview**: bounded loops and offline jobs look like N+1. |
| BE012 Insecure CORS | 1/35 (3%) | 1/1 (100%) | Fixed: an open origin is reported only together with credentials. |
| FE001 XSS through a raw HTML sink | 20/61 (33%) | 20/30 (67%) | Fixed: template `\|safe` only on user- or model-looking values, plain-text email templates, literal strings, vendored bundles. **Preview**: the source of the HTML is often not visible in the file. |
| DATA007 Env var missing from .env.example | 6/34 (18%) | 6/12 (50%) | Fixed: `"X" in os.environ` guards, `if x:` and default-assigning checks, ternaries, strings in prompts. **Preview**: optional-by-design settings look the same as required ones. |
| BE001 SQL injection | 1/19 (5%) | 1/1 (100%) | Fixed: `Promise.all(callback)` matched as a query; constant identifiers in migrations. |
| BE008 Open redirect | 1/14 (7%) | 1/2 (50%) | Fixed: `url_for()`, `reverse()`, `redirect(model)`, own origin plus fixed path. Not enough data left. |
| BE003 Dynamic code execution | 0/12 (0%) | 0/4 | Fixed: minified and vendored bundles, a module's own `eval()` function. Not enough data: the 4 left are library code that runs code by design. |
| AUTH005 Table without RLS | 2/12 (17%) | 2/2 (100%) | Fixed: RLS enabled by a setup script that runs the SQL. |
| SEC004 Hard-coded signing secret | 4/13 (31%) | 4/4 (100%) | Fixed: `examples/`, an error message naming `cookieParser("secret")`, base settings that production.py replaces. |
| AUTH006 Permissive policy | 12/19 (63%) | 12/13 (92%) | Fixed: policies `TO service_role`. |
| AUTH010 Login without rate limit | 8/13 (62%) | 8/8 (100%) | Fixed: token-based resets, routes that take no credential, superuser-only routes. |
| AUTH003 IDOR | 0/6 (0%) | 0/2 | Fixed: `req.auth?.user?.id`, `current_user().id`, admin-only routes. Not enough data. |
| DATA006 Timestamp without time zone | 14/19 (74%) | 14/14 (100%) | Fixed by excluding library `examples/`. |
| BE018 No server-side validation | 6/11 (55%) | 6/9 (67%) | Fixed: `npm:zod` imports. **Preview**: hand-written validation is not recognised. |
| UI006 Destructive action without confirmation | 5/7 (71%) | 5/7 (71%) | **Preview**: a confirmation in a parent component, or a local-state removal, is not seen. |
| SEC003 High-entropy secret | 9/12 (75%) | 9/11 (82%) | Fixed: `pub_`/`pk_` public keys, base settings keys. **Preview**: other public client keys and demo tokens. |
| DATA010 Writes without a transaction | 8/9 (89%) | 8/9 (89%) | **Preview**: writes in separate webhook branches and helpers are counted together. |
| UI001, UI002, UI010 | 18/21, 35/40, 0/2 | 18/18, 35/36, 0/0 | Fixed: images and lorem ipsum inside HTML and Django template comments; backdrop overlays that close a dialog. |
| QA001, FE004, FE005, CFG006, BE011, BE015, QA005, QA007, DATA003 | various | all at or near 100%, or no false positive left | Fixed: Django `tests.py` counts as tests; Web Worker message channels; WebAuthn ids; dev and test settings files; `random.SystemRandom()`; `__setitem__` raising NotImplementedError; PEP 508 direct references and `djmoney`; `ALTER COLUMN ... USING`. |

Rules with fewer than 5 labelled findings are shown as "not enough data" in RESULTS.md together with their
seeded recall; their false positives were fixed where the cause was clear (see above). Every rule except
AI001 (needs a model), the three network rules and SEC006 (needs a git-tracked file) has at least one
seeded case, and seeded recall is 100% for all of them.
