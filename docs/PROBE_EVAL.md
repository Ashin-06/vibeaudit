# `vibeaudit probe` on deliberately vulnerable apps

First measurement of the dynamic checks (`vibeaudit probe`, as merged in #71) against five deliberately vulnerable
apps. Each app ran in Docker from its official image or repository, published on 127.0.0.1 only, and was removed
afterwards. Settings: `--rate 10 --max-requests 2000`, **no `--auth`/`--auth2`**, so the auth-bypass and IDOR checks did
not run. The probe was not tuned on these apps; the causes found below are follow-ups, to be measured later on
different apps.

| App | Routes in the model | Requests | Confirmed | True | False |
| --- | --- | --- | --- | --- | --- |
| OWASP Juice Shop | 118 (source checkout incomplete, see below) | 157 | 11 | 9 | 2 |
| DVGA (GraphQL) | 19 | 32 | 2 | 1 | 1 |
| pygoat | 151 | 686 | 9 | 3 | 6 |
| NodeGoat | 2 | 5 | 1 | 1 | 0 |
| crAPI | 51 | 189 | 12 | 1 | 11 |
| **Total** | | | **35** | **15** | **20** |

Precision of the confirmations: 15/35 (43%). No high or critical finding was confirmed.

## Recall by class (known vulnerabilities, from each app's published list)

| Class | Present in | Confirmed | Why it was missed |
| --- | --- | --- | --- |
| SQL / NoSQL injection | Juice Shop, DVGA, pygoat, NodeGoat, crAPI | 0/5 | Juice Shop's login and search take JSON bodies; the probe sends form-encoded bodies and only query parameters it finds in handler code. DVGA's injection sits behind GraphQL arguments, NodeGoat's behind routes the model did not find |
| Reflected / stored XSS | all five | 0/5 | Most are DOM or stored XSS in single-page frontends, which a request/response check cannot see; reflected ones take JSON or GraphQL input |
| Path traversal | Juice Shop, pygoat | 0/2 | Juice Shop's is a null-byte file download (`/ftp/...%2500.md`), not a parameter; pygoat's lab parameter was not found |
| SSRF | Juice Shop, DVGA, pygoat, crAPI | 0/4 | Each takes the URL in a JSON or GraphQL body, or behind sign-in |
| Open redirect | Juice Shop, NodeGoat | 0/2 | Juice Shop's `/redirect?to=` uses an allow-list bypass the canary host does not exercise; NodeGoat's route was not in the model |
| IDOR / broken object access | all five | not run | needs `--auth` and `--auth2` |
| Authentication bypass | all five | not run | needs `--auth` |
| Login without rate limiting | Juice Shop, pygoat, crAPI | 1/3 | Juice Shop's `/rest/user/login` confirmed; crAPI's OTP brute force got HTTP 415 (form body to a JSON API); pygoat's lab route was not deployed at that path |
| Verbose errors / stack traces | Juice Shop, pygoat | 2/2 | Juice Shop (7 routes, one cause) and pygoat's Django debug page |
| Missing security headers | all five | 5/5 | not a listed vulnerability in most of these apps, but true in each |
| Prompt injection (system prompt) | crAPI chatbot | 0/1 | the chatbot takes JSON behind sign-in |

## False positives (20)

- **AUTH010 on endpoints the probe never reached:** HTTP 404 (dvga 1, pygoat 5), 415 (crAPI 6, a form body sent to a
  JSON API) or 500 (pygoat 1). Twelve identical non-429 answers do not show that a login was processed.
- **AUTH010 on routes that are not credential checks:** a passkey options and verify pair (Juice Shop 2), `reset-test-users`
  and a chatbot reset (crAPI 2), and three signed-in account routes that answered 401 (crAPI 3).

## Structural limits seen

- **Route model:** NodeGoat yielded 2 routes (its routes are registered through a function the model does not follow).
  The Juice Shop checkout was partly incomplete on Windows (long paths), so its count is a lower bound. DVGA is one
  GraphQL endpoint, and the probe does not build GraphQL request shapes yet.
- **Request shapes:** the probe sends query parameters and form bodies. Most modern APIs here take JSON, so injected
  values never reached the handler.
- **Sign-in:** most vulnerable endpoints sit behind authentication, and this run had none.

## Follow-ups (not done here; to be measured on different apps)

1. AUTH010: count a burst only when the first answers show the request was processed (200, 400 or 401 with a body),
   never 404, 405, 415 or 5xx. Require a credential field in the handler (password, otp, token, code).
2. JSON bodies: send injection payloads as JSON when the handler reads JSON (req.body with express.json(),
   request.json, @RequestBody), and retry with JSON after a 415.
3. GraphQL: build queries and mutations from the schema (introspection, or the resolver map) and probe their arguments.
4. Route model: follow Express routers registered through functions (NodeGoat's `index.js` pattern).
5. Run with `--auth` / `--auth2` against apps with seeded users, to measure the auth-bypass and IDOR checks.

## Second run: probe v3 (VAmPI, DVWA, DVNA)

Rerun on Docker targets after probe v2/v3 improvements (JSON body retries, GraphQL introspection, plain-PHP routes, HTML form sign-in with CSRF tokens, OpenAPI route discovery, HTML GET/POST form submit defaults, logout-path guard, and `Cookie` header merging):

| App | Routes in the model | Requests | Confirmed | True | False | Findings confirmed |
| --- | --- | --- | --- | --- | --- | --- |
| VAmPI (`erev0s/vampi:latest`, `--login /users/v1/login` two-user JSON) | 14 (via `openapi_specs/openapi3.yml`) | 87 | 3 | 3 | 0 | `BE001` (SQLi on `GET /users/v1/{username}`), `AUTH010` (login rate limit), `CFG019` (headers) |
| DVWA (`vulnerables/web-dvwa:latest`, `--auth "Cookie: security=low"` + `--login-form /login.php` CSRF) | 51 | 976 | 5 | 5 | 0 | `BE001` (SQLi on `vulnerabilities/brute/index.php`), 3x `FE001` (XSS on `csp`, `xss_r`, `xss_s`), `CFG019` (headers) |
| DVNA (`dvna-9ba473add536` `Dockerfile` on `node:carbon` + `mysql:5.7`) | - | - | - | - | - | Not run: upstream container exits at startup loading native `libxmljs/lib/bindings.js` on Node 8 |
| **Total (runnable apps)** | | | **8** | **8** | **0** | **100% precision** (up from 43% in the first run; 5 high-severity SQLi/XSS findings confirmed) |

### Third check: authenticated two-user smoke test (OWASP Juice Shop, v0.13.0)

- Target: `bkimminich/juice-shop:latest` in Docker with two freshly created users passed via `--login /rest/user/login --login-json ... --login2-json ...`.
- Result: 21 requests across 8 OpenAPI-defined routes; both sessions authenticated cleanly (no auth-failure warning), confirming `CFG019` (`1 confirmed`, `0 false positives`).
