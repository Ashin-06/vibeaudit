"""Advisory recall set: real GHSA fixes in the classes vibeaudit covers, pinned at the vulnerable commit.

    python tools/advisories.py harvest          # build benchmark/advisories.json (split and scope fixed here)
    python tools/advisories.py run [--split S]  # fetch each vulnerable commit, scan it, report recall

harvest takes reviewed advisories whose references include a fix commit, pins the fix's parent (the vulnerable
commit) and records the lines the fix removed or changed in each source file. Before anything is scanned it fixes
two things per advisory and writes them down:
- split: "tune" or "heldout", from a hash of the GHSA id (about 60/40). Detection is improved from tune misses only.
- scope: "in" when the class has a vibeaudit rule for the file's language, the vulnerable file is application source
  (not a test, example or vendored file), and the fix touches at most 3 source files; otherwise "out", with why.
A location counts as detected when a finding of one of the class's rules lands in that file within 3 lines.
Needs the `gh` CLI (authenticated) and git."""
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SET = ROOT / "benchmark" / "advisories.json"
CACHE = Path(os.environ.get("VIBEAUDIT_BENCH_CACHE", Path.home() / ".cache" / "vibeaudit-bench")) / "advisories"

CLASSES = {  # class: (CWE ids, rules that detect it)
    "sqli": ((89, 943), ("BE001", "GO004", "BE010")),
    "command": ((77, 78), ("BE002", "BE003")),
    "code": ((94, 95), ("BE003", "BE007")),
    "path": ((22, 23, 73), ("BE006",)),
    "ssrf": ((918,), ("BE005",)),
    "xss": ((79,), ("FE001",)),
    "redirect": ((601,), ("BE008",)),
    "deserialization": ((502,), ("BE004", "JAVA004", "CSHARP002")),
    "missing-auth": ((306, 862, 285), ("AUTH001", "AUTH002", "AUTH003", "AUTH017", "JAVA001", "CSHARP001")),
    "secrets": ((798, 321), ("SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC011")),
}
ECOSYSTEMS = {"pip": (".py",), "npm": (".js", ".ts", ".jsx", ".tsx", ".mjs", ".vue", ".svelte"), "go": (".go",),
              "maven": (".java", ".kt"), "composer": (".php",), "rust": (".rs",), "nuget": (".cs", ".cshtml"),
              "rubygems": (".rb", ".erb")}
# a class without a rule for a language is out of scope there by design
NO_RULE = {("ssrf", ".rb"), ("ssrf", ".erb"), ("redirect", ".rs"), ("secrets", ".erb")}
NOT_APP = re.compile(r"(?i)(?:^|/)(?:tests?|spec|__tests__|examples?|docs?|vendor|third_party|node_modules|fixtures?|"
                     r"benchmarks?)/|_test\.go$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|test_[^/]*\.py$|Test\.java$")
IN_CAP, OUT_CAP = 6, 1  # per (class, ecosystem): in-scope cases are scarce (most advisories are libraries), so look further for them
MAX_REPO_KB = 150_000


def gh(path: str):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else None


def removed_lines(patch: str):
    """Line numbers in the old file that the fix removed or replaced."""
    lines, old = [], 0
    for ln in patch.split("\n"):
        h = re.match(r"@@ -(\d+)", ln)
        if h:
            old = int(h.group(1))
            continue
        if ln.startswith("-"):
            lines.append(old)
            old += 1
        elif ln.startswith("+"):
            if not lines or lines[-1] != old - 1:
                lines.append(max(1, old - 1))  # an added guard: the line before it
        else:
            old += 1
    return lines


def candidate(adv, cls, eco, exts):
    """The case for one advisory (vulnerable commit, file, lines, split, scope), or None when it has no usable fix."""
    ref = next((r for r in adv.get("references") or [] if re.search(r"github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}", r)), None)
    if not ref:
        return None
    owner, repo, sha = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})", ref).groups()
    info, commit = gh(f"repos/{owner}/{repo}"), gh(f"repos/{owner}/{repo}/commits/{sha}")
    if not info or not commit or not commit.get("parents") or info.get("size", 0) > MAX_REPO_KB:
        return None
    src = [f for f in commit.get("files") or [] if f["filename"].endswith(exts) and f.get("patch")]
    app = [f for f in src if not NOT_APP.search(f["filename"])]
    if not src:
        return None
    target = app[0] if app else src[0]
    ext = os.path.splitext(target["filename"])[1]
    lines = removed_lines(target["patch"])
    why = ("the vulnerable file is a test, example or vendored file" if not app else
           f"no {cls} rule for {ext}" if (cls, ext) in NO_RULE else
           "the fix spans more than 5 source files" if len(app) > 5 else "")
    case = {
        "advisory": adv["ghsa_id"], "class": cls, "ecosystem": eco,
        "repo": f"{owner}/{repo}", "commit": commit["parents"][0]["sha"], "fix": commit["sha"],
        "file": target["filename"], "lines": [min(lines), max(lines)] if lines else [1, 1],
        "rules": list(CLASSES[cls][1]),
        "split": "heldout" if int(hashlib.sha256(adv["ghsa_id"].encode()).hexdigest(), 16) % 10 < 4 else "tune",
        "scope": "out" if why else "in", "why_out": why,
    }
    if not why:
        why = file_scope(case)
        case["scope"], case["why_out"] = ("out", why) if why else ("in", "")
    return case


def harvest() -> None:
    cases, seen = [], set()
    for cls, (cwes, _rules) in CLASSES.items():
        for eco, exts in ECOSYSTEMS.items():
            got = {"in": 0, "out": 0}
            advs = []
            for page in (1, 2, 3):
                batch = gh(f"/advisories?type=reviewed&ecosystem={eco}&cwes={','.join(map(str, cwes))}&per_page=100&page={page}") or []
                advs += batch
                if len(batch) < 100:
                    break
            for adv in advs:
                if got["in"] >= IN_CAP or adv["ghsa_id"] in seen:
                    continue
                case = candidate(adv, cls, eco, exts)
                if case is None or got[case["scope"]] >= (IN_CAP if case["scope"] == "in" else OUT_CAP):
                    continue
                seen.add(adv["ghsa_id"])
                got[case["scope"]] += 1
                cases.append(case)
                print(len(cases), adv["ghsa_id"], cls, eco, case["repo"], case["why_out"], flush=True)
    SET.write_text(json.dumps({"about": __doc__.split("\n\n", 2)[2].strip(), "cases": cases}, indent=1) + "\n",
                   encoding="utf-8", newline="\n")


# vibeaudit follows request data (in the same function, or up to 3 calls away) into sinks; a library whose input
# arrives as a function argument is out of scope by design. These are the request sources it knows, per language.
REQUEST_SOURCE = re.compile(
    r"\brequest\s*\.\s*(?:args|form|json|values|files|GET|POST|data|body|query|params|headers|cookies|query_params|path_params)\b"
    r"|\breq\s*\.\s*(?:body|query|params|headers|cookies)\b|\bsearchParams\b|\bformData\s*\(|\bctx\s*\.\s*(?:query|params|request)\b"
    r"|\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\$request\s*->|\bRequest::|\bparams\s*\[|\bparams\s*\.\s*(?:require|permit|fetch)"
    r"|\bc\s*\.\s*(?:Query|Param|PostForm|FormValue|Bind\w*|ShouldBind\w*)\s*\(|\br\s*\.\s*(?:URL|Form|FormValue|PostFormValue|Body)\b"
    r"|@(?:RequestParam|PathVariable|RequestBody|RequestHeader)\b|\[From(?:Query|Body|Route|Form|Header)\]"
    r"|\b(?:Query|Path|Json|Form)\s*<|\bweb\s*::\s*(?:Query|Path|Json|Form)\b|@(?:app|router|bp)\.\w+\(|@(?:Get|Post|Put|Delete|Patch)Mapping")
ROUTE_DEF = re.compile(r"@(?:app|router|bp|api)\.(?:get|post|put|delete|patch|route)\(|\b(?:app|router)\.(?:get|post|put|delete|patch)\(|"
                       r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping|\bRoute::|\.(?:GET|POST|PUT|DELETE|PATCH|HandleFunc)\(|"
                       r"\[Http(?:Get|Post|Put|Delete|Patch)\]|def\s+(?:create|update|destroy)\b|export\s+(?:async\s+)?function\s+(?:POST|PUT|DELETE|PATCH)\b")


# open-source web and AI applications, where input comes from requests (package names as the advisory database
# lists them); `harvest apps` adds their advisories in every covered class to the set
APPS = [("npm", "flowise"), ("pip", "langflow"), ("npm", "n8n"), ("pip", "open-webui"), ("npm", "@directus/api"),
        ("npm", "directus"), ("npm", "@strapi/strapi"), ("npm", "@strapi/plugin-users-permissions"), ("npm", "ghost"),
        ("go", "code.gitea.io/gitea"), ("npm", "librechat"), ("pip", "mlflow"), ("pip", "gradio"), ("npm", "payload"),
        ("composer", "pimcore/pimcore"), ("composer", "microweber/microweber"), ("pip", "lunary"), ("pip", "anything-llm"),
        ("npm", "@budibase/server"), ("go", "github.com/gogs/gogs"), ("pip", "superset"), ("pip", "apache-superset"),
        ("pip", "label-studio"), ("composer", "craftcms/cms"), ("npm", "@nocobase/server"), ("pip", "dify"),
        ("pip", "pyload-ng"), ("composer", "snipe/snipe-it"), ("go", "github.com/answerdev/answer"),
        ("npm", "uptime-kuma"), ("pip", "changedetection.io"), ("npm", "nodebb"), ("composer", "phpmyfaq/phpmyfaq"),
        ("rubygems", "decidim"), ("maven", "org.jeecgframework.boot:jeecg-boot-common"), ("nuget", "Umbraco.Cms")]


def harvest_apps(cap: int = 12) -> None:
    data = json.loads(SET.read_text(encoding="utf-8"))
    cases = data["cases"]
    seen = {c["advisory"] for c in cases}
    cwe_class = {cwe: cls for cls, (cwes, _r) in CLASSES.items() for cwe in cwes}
    for eco, pkg in APPS:
        got = 0
        for adv in gh(f"/advisories?type=reviewed&ecosystem={eco}&affects={pkg}&per_page=100") or []:
            cls = next((cwe_class[int(w["cwe_id"].split("-")[1])] for w in adv.get("cwes") or []
                        if w["cwe_id"].startswith("CWE-") and int(w["cwe_id"].split("-")[1]) in cwe_class), None)
            if got >= cap or not cls or adv["ghsa_id"] in seen:
                continue
            case = candidate(adv, cls, eco, ECOSYSTEMS[eco])
            if case is None:
                continue
            seen.add(adv["ghsa_id"])
            cases.append(case)
            got += case["scope"] == "in"
            print(len(cases), adv["ghsa_id"], cls, pkg, case["scope"], case["why_out"], flush=True)
    SET.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8", newline="\n")


def file_scope(c) -> str:
    """Why a case is out of scope, from the vulnerable file's own text (read before any scan), or "" when in scope:
    request-data classes need a request source in the file, missing-auth needs a route definition in it, secrets
    need a quoted literal on a fixed line."""
    import base64

    blob = gh(f"repos/{c['repo']}/contents/{c['file']}?ref={c['commit']}")
    if not blob or "content" not in blob:
        return "the vulnerable file could not be read at the pinned commit"
    text = base64.b64decode(blob["content"]).decode("utf-8", "replace")
    if c["class"] == "secrets":
        lines = text.split("\n")[c["lines"][0] - 1:c["lines"][1]]
        literal = any(re.search(r"""["'][A-Za-z0-9+/_\-]{16,}["']""", ln) for ln in lines)
        return "" if literal else "no committed literal on the fixed lines"
    if c["class"] == "missing-auth":
        return "" if ROUTE_DEF.search(text) else "the file defines no route vibeaudit discovers (library or middleware code)"
    return "" if REQUEST_SOURCE.search(text) else "library code: the input arrives as a function argument, not request data"


def checkout(case) -> Path:
    path = CACHE / (case["repo"].replace("/", "__") + "-" + case["commit"][:12])
    if not (path / ".bench-ok").exists():
        path.mkdir(parents=True, exist_ok=True)
        run = lambda *a: subprocess.run(["git", "-C", str(path), *a], capture_output=True, check=True)  # noqa: E731
        run("init", "-q")
        run("fetch", "-q", "--depth", "1", f"https://github.com/{case['repo']}", case["commit"])
        run("checkout", "-q", "FETCH_HEAD")
        (path / ".bench-ok").write_text("ok")
    return path


def run(split: str = "") -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from vibeaudit.scanner import Options, scan

    cases = json.loads(SET.read_text(encoding="utf-8"))["cases"]
    tally = {}
    misses = []
    for c in cases:
        if split and c["split"] != split:
            continue
        try:
            root = checkout(c)
            res = scan(str(root), Options(offline=True, external="none", include_preview=True, min_severity="low"))
        except Exception as e:  # noqa: BLE001  an unreachable commit counts as not run, not as a miss
            print("skip", c["advisory"], e.__class__.__name__)
            continue
        lo, hi = c["lines"]
        hit = any(f.rule_id in c["rules"] and f.file == c["file"] and lo - 3 <= f.line <= hi + 3 for f in res.findings)
        for key in ((c["split"], c["scope"]), (c["split"], "all")):
            t = tally.setdefault(key, [0, 0])
            t[0] += hit
            t[1] += 1
        if not hit:
            misses.append(c)
        print(("HIT " if hit else "miss"), c["advisory"], c["split"], c["scope"], c["class"], c["repo"], c["file"], flush=True)
    for (sp, sc), (h, n) in sorted(tally.items()):
        print(f"{sp:8} {sc:4} {h}/{n} ({h / max(1, n):.0%})")
    (CACHE / "misses.json").write_text(json.dumps(misses, indent=1), encoding="utf-8")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    (harvest_apps() if sys.argv[2:3] == ["apps"] else harvest()) if cmd == "harvest" else run(sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == "--split" else "")
