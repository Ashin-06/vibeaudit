"""Code-completeness rules (QA005-QA008), including every false alarm found on real repositories."""
from vibeaudit.scanner import Options, scan


def _rules(tmp_path, rule_prefix="QA00"):
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith(rule_prefix) and f.rule_id not in ("QA001", "QA002"))


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_a_settings_folder_named_like_a_package_does_not_shadow_it(tmp_path):
    write(tmp_path, "requirements.txt", "django==5.0\n")
    write(tmp_path, "config/django/__init__.py", "")
    write(tmp_path, "config/urls.py", "from django.conf import settings\nfrom django.urls import path\n")
    assert _rules(tmp_path) == []


def test_relative_and_local_absolute_imports(tmp_path):
    write(tmp_path, "requirements.txt", "flask==3.0\n")
    write(tmp_path, "app/__init__.py", "")
    write(tmp_path, "app/money.py", "def to_cents(x):\n    return x\n")
    write(tmp_path, "app/views.py", "from .money import to_cents\nfrom .money import from_cents\nfrom .tax import rate\n"
                                    "from app.money import to_cents as tc\nfrom app.nothing import x\nfrom . import money\n")
    assert _rules(tmp_path) == [("app/views.py", 2, "QA006"), ("app/views.py", 3, "QA006"), ("app/views.py", 5, "QA006")]


def test_undeclared_python_imports(tmp_path):
    write(tmp_path, "requirements.txt", "django-structlog==9.1\ndjango-filter==25.2\nPyYAML==6.0\nrequests==2.32\n")
    write(tmp_path, "a.py", "import structlog\nimport django_filters\nimport yaml\nimport requests\nimport os\nimport redis\n"
                            "try:\n    import ujson\nexcept ImportError:\n    ujson = None\n")
    assert _rules(tmp_path) == [("a.py", 6, "QA007")]


def test_no_python_manifest_means_no_undeclared_findings(tmp_path):
    write(tmp_path, "a.py", "import redis\n")
    assert _rules(tmp_path) == []


def test_stubs(tmp_path):
    write(tmp_path, "a.py",
          "import abc\nimport click\n\n@app.post('/api/pay')\ndef pay():\n    pass\n\n"
          "def refund():\n    raise NotImplementedError\n\n"
          "@click.group()\ndef cli():\n    pass\n\n"
          "def noop_fallback(*a):\n    pass\n\n"
          "class Base(abc.ABC):\n    @abc.abstractmethod\n    def run(self):\n        raise NotImplementedError\n")
    assert _rules(tmp_path) == [("a.py", 5, "QA005"), ("a.py", 8, "QA005")]


def test_js_destructured_exports_are_found(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next-auth": "5.0.0"}}')
    write(tmp_path, "auth.ts", "export const {\n  handlers: { GET, POST },\n  auth,\n  signIn,\n} = NextAuth({});\n")
    write(tmp_path, "a.ts", 'import { auth, signIn, signOut } from "./auth";\n')
    assert _rules(tmp_path) == [("a.ts", 1, "QA006")]


def test_tsconfig_aliases_with_star_strings_and_base_url(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "web/package.json", '{"dependencies": {"react": "18.0.0"}}')
    write(tmp_path, "web/tsconfig.json",
          '{\n  // comment\n  "compilerOptions": {\n    "baseUrl": ".",\n    "paths": { "@/*": ["./*"] },\n  },\n'
          '  "include": ["**/*.ts", "**/*.tsx"],\n}\n')
    write(tmp_path, "web/lib/server/token.ts", "export const token = 1;\n")
    write(tmp_path, "web/utils/helpers.ts", "export function help() {}\n")
    write(tmp_path, "web/styles/main.css", "body {}\n")
    write(tmp_path, "web/app/page.tsx", 'import { token } from "@/lib/server/token";\nimport { help } from "utils/helpers";\n'
                                        'import { gone } from "@/lib/missing";\nimport x from "styles/main.css";\n')
    assert _rules(tmp_path) == [("web/app/page.tsx", 3, "QA006")]


def test_undeclared_js_packages(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"@tiptap/react": "2.0.0", "next": "14.0.0", "react": "18.0.0"}}')
    write(tmp_path, "a.ts", 'import { Editor } from "@tiptap/core";\nimport Image from "next/image";\nimport fs from "node:fs";\n'
                            'import path from "path";\nimport _ from "lodash";\nimport type { X } from "zod";\nimport logo from "/logo.svg";\n')
    assert _rules(tmp_path) == [("a.ts", 5, "QA007")]


def test_esm_typescript_js_extension_and_deno_functions(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {}}')
    write(tmp_path, "src/util.ts", "export const u = 1;\n")
    write(tmp_path, "src/main.ts", 'import { u } from "./util.js";\n')
    write(tmp_path, "supabase/functions/f/index.ts", 'import { serve } from "https://deno.land/std/http/server.ts";\nimport x from "openai";\n')
    assert _rules(tmp_path) == []


def test_ts_nocheck_and_not_implemented(tmp_path):
    write(tmp_path, "a.ts", "// @ts-nocheck\nexport function f() {\n  throw new Error('Not implemented yet');\n}\n")
    write(tmp_path, "b.d.ts", "// @ts-nocheck\n")
    assert _rules(tmp_path) == [("a.ts", 1, "QA008"), ("a.ts", 3, "QA005")]
