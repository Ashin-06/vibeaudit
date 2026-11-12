"""AI-slop rules added in 0.8.4 (QA009-QA011)."""
import time

from vibeaudit import slopscan
from vibeaudit.files import Project
from vibeaudit.jsscan import js_views
from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

NEW = ("QA009", "QA010", "QA011")


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id in (rules or NEW))


def test_new_rules_start_as_preview():
    assert all(RULES[r].preview and RULES[r].preview_reason for r in NEW)


def test_pages_router_code_in_the_app_router(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0", "react": "19.0.0"}}')
    write(tmp_path, "app/layout.tsx", "export default function RootLayout({ children }) { return children; }\n")
    write(tmp_path, "app/posts/page.tsx",
          "import { useRouter } from 'next/router';\n"                                       # 1
          "export async function getServerSideProps() { return { props: {} }; }\n"           # 2
          "export default function Page() { return null; }\n")
    write(tmp_path, "app/nav.tsx", "'use client';\nimport { useRouter } from 'next/navigation';\n"
          "export const metadata = { title: 'x' };\n")                                       # 3
    write(tmp_path, "app/about/page.tsx", "export const metadata = { title: 'About' };\nexport default function A() { return null; }\n")
    write(tmp_path, "pages/old.tsx", "import { useRouter } from 'next/router';\nexport async function getServerSideProps() { return { props: {} }; }\n")
    assert found(tmp_path, "QA009") == [("app/nav.tsx", 3, "QA009"), ("app/posts/page.tsx", 1, "QA009"),
                                        ("app/posts/page.tsx", 2, "QA009")]


def test_no_app_router_no_finding(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0"}}')
    write(tmp_path, "app/page.tsx", "export async function getServerSideProps() { return { props: {} }; }\n")
    assert found(tmp_path, "QA009") == []


def test_made_up_data_as_a_fallback(tmp_path):
    write(tmp_path, "src/api.ts",
          "import { mockPosts } from './data';\n"
          "export async function load() {\n  try {\n    const r = await fetch('/api/posts');\n    return await r.json();\n"
          "  } catch (e) {\n    return mockPosts;\n  }\n}\n"                                  # 7
          "export function list(data) {\n  return data?.items ?? MOCK_ITEMS;\n}\n"            # 11
          "export function ok(data) {\n  try { return data.x; } catch { return null; }\n}\n")
    write(tmp_path, "src/flagged.ts", "const USE_MOCKS = true;\nexport function f(d) { return d ?? mockPosts; }\n")
    write(tmp_path, "src/mocks/handlers.ts", "export const h = (d) => d ?? fakeUser;\n")
    write(tmp_path, "svc.py",
          "import requests\n\ndef users():\n    try:\n        return requests.get('https://x').json()\n"
          "    except Exception:\n        return MOCK_USERS\n\n"                                  # 7
          "def items(resp):\n    return resp.get('items') or get_fake_items()\n\n"                # 10
          "def safe():\n    try:\n        return 1\n    except Exception:\n        return None\n")
    assert found(tmp_path, "QA010") == [("src/api.ts", 7, "QA010"), ("src/api.ts", 11, "QA010"),
                                        ("svc.py", 7, "QA010"), ("svc.py", 10, "QA010")]


def test_same_function_in_several_files(tmp_path):
    body = "export function formatPrice(cents: number): string {\n  const d = cents / 100;\n  const s = d.toFixed(2);\n  return '$' + s;\n}\n"
    write(tmp_path, "package.json", '{"name": "web"}')
    write(tmp_path, "src/a.ts", body)
    write(tmp_path, "src/b.ts", "import x from 'y';\n\n" + body)                             # 3
    write(tmp_path, "src/c.ts", body.replace("toFixed(2)", "toFixed(0)"))                     # different code
    write(tmp_path, "packages/other/package.json", '{"name": "other"}')
    write(tmp_path, "packages/other/util.ts", body)                                          # another package
    py = "def slugify(text):\n    text = text.lower()\n    text = text.strip()\n    text = text.replace(' ', '-')\n    return text\n"
    write(tmp_path, "app/one.py", py)
    write(tmp_path, "app/two.py", "import os\n" + py)                                        # 2
    write(tmp_path, "app/route_a.ts", "export async function GET() {\n  const a = 1;\n  const b = 2;\n  return a + b;\n}\n")
    write(tmp_path, "app/route_b.ts", "export async function GET() {\n  const a = 1;\n  const b = 2;\n  return a + b;\n}\n")
    assert found(tmp_path, "QA011") == [("app/two.py", 2, "QA011"), ("src/b.ts", 3, "QA011")]


def test_standalone_scripts_and_deploy_units_are_not_duplicates(tmp_path):
    body = "export function cors(origin: string) {\n  const a = origin;\n  const b = a + '/';\n  return b;\n}\n"
    write(tmp_path, "package.json", '{"name": "web"}')
    write(tmp_path, "src/lib/cors.ts", body)
    write(tmp_path, "supabase/functions/one/index.ts", body)
    write(tmp_path, "supabase/functions/two/index.ts", body)                                # 1
    py = "def scope():\n    a = 1\n    b = 2\n    c = 3\n    return a + b + c\n"
    write(tmp_path, "benchmarks/one.py", py)
    write(tmp_path, "benchmarks/two.py", py)
    write(tmp_path, "agent/skills/a/example_engine.py", py)
    write(tmp_path, "agent/skills/b/example_engine.py", py)
    assert found(tmp_path, "QA011") == [("supabase/functions/two/index.ts", 1, "QA011")]


def test_optional_import_stand_ins_are_not_made_up_data(tmp_path):
    write(tmp_path, "serving.py", "try:\n    import ssl\nexcept ImportError:\n    ssl = _SslDummy()\n")
    assert found(tmp_path, "QA010") == []


def test_slop_checks_are_linear_on_hostile_input(tmp_path):
    # the slop checks alone, on lexer views, so the time measured is theirs and not the rest of the scanner's
    nl = "\n"
    write(tmp_path, "a.ts", "catch (" * 5000 + nl + ("x ?? mockA" + nl) * 5000 + (nl + "function f(") * 5000
          + (nl + "function f() {") * 5000 + (nl + "export const g = () => {") * 5000 + (nl + "} catch {") * 5000)
    fn = "export function h() {" + nl + ("  a();" + nl) * 5 + "}" + nl
    write(tmp_path, "b.ts", fn * 5000)
    write(tmp_path, "c.ts", fn * 5000)
    py = "def h():" + nl + ("    a()" + nl) * 5
    handler = "def g():" + nl + "    try:" + nl + "        x" + nl + "    except E:" + nl + "        return mock_a or fake_b" + nl
    write(tmp_path, "d.py", py * 5000 + handler * 3000)
    project = Project(tmp_path)
    for sf in project.files:
        if sf.kind == "js":
            sf.cache["views"] = js_views(sf.text or "")
    start = time.time()
    slopscan.run(project, lambda *a, **k: None)
    assert time.time() - start < 15
