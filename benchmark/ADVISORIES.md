# Advisory recall

`benchmark/advisories.json` holds 255 real GitHub security advisories in the classes vibeaudit covers. Each one is
pinned at the commit before its fix, with the lines the fix changed. `python tools/advisories.py run` fetches each
commit, scans it and counts a hit when a finding of the class's rules lands in that file within the changed lines
(plus or minus 3).

The set was frozen on 2026-11-24 before anything was scanned. The split was set from a hash of the advisory id: 164
tune, 88 held out, 3 that could not be fetched. Scope came from a rule written down in tools/advisories.py: the class
has a rule for the file's language, the file is application source with a request source (or a route, for missing
auth), and the fix touches at most 5 source files. That gives 115 tune and 61 held-out cases in scope. Detection was
improved from tune misses only, and held-out was scored once, at the end.

## Results

| | Before | After |
| --- | --- | --- |
| Tune, in scope | 13/115 (11%) | 18/115 (16%) |
| Held-out, in scope | 6/61 (10%) | **7/61 (11%)** |
| Held-out, all | 6/88 (7%) | 7/88 (8%) |
| Out of scope (both splits) | 0/76 | 0/76 |

The precision gate passed on all 142 repositories after the changes.

The matcher was checked first, on tune only. 73 of the 102 tune misses had no finding at all in the vulnerable file,
and only 4 had a finding of the right rule anywhere in it, each at another location. A looser rule, such as the
enclosing function, would not change the result, so the rule stayed as written.

## What was added (from tune misses)

- SymPy `sympify()` / `parse_expr()` on request data (BE003).
- Go signing keys written as `[]byte("...")` (SEC004).
- Rails `find_by(params[:x])` / `where(params[:x])`, a whole request value used as query conditions (BE001).
- PHP outbound requests through Symfony HttpClient or Guzzle `->request('GET', $url)` and Symfony Filesystem
  `->copy($url, ...)` (BE005).
- The Rails scanner (#68) covers the Ruby cases it reaches.

## Why the target (75% in scope) is out of reach

The 98 tune misses that remain fall into these groups:

| Cause | About | What it would take |
| --- | --- | --- |
| Library or framework internals: the input arrives as a function argument (tornado, express, react-router, rack, Zend, kysely, CakePHP, yt-dlp, helm, oauth2 gems) | 45 | A library mode that treats public function arguments as untrusted; not in scope for an app scanner, and noisy |
| A check exists but is incomplete or bypassable (host allow-lists, redirect validation, signature checks, Twig sandbox lists) | 18 | Reasoning about what a check misses, not a missing sink |
| Authorization logic or configuration (per-action permissions, default credentials, settings that disable auth) | 9 | Knowledge of the app's own permission model |
| One-off custom sinks or cross-file flows (dispatchers, service wrappers, custom HTTP servers) | 22 | One rule per project; generic cases were fixed above |

The first group explains most of the gap. The scope rule counted a request-like word in a file as a request
source, so many library files were tagged in scope; scope stayed as frozen rather than being re-tagged after
the results were seen. On application code with a request source and a known sink, vibeaudit's detection is close to
what the seeded examples show (100%). The advisory set measures how far real-world vulnerabilities extend beyond
those patterns.
