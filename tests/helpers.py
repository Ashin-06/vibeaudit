"""Shared test helpers: materialise a fixture with freshly generated fake secrets and compare findings."""
from __future__ import annotations

import base64
import json
import re
import shutil
from pathlib import Path
from typing import Dict, Set, Tuple

FIXTURES = Path(__file__).parent / "fixtures"
MARKER = re.compile(r"expect:\s*([A-Z]+[0-9]+(?:\s*,\s*[A-Z]+[0-9]+)*)")
MARKER_ONLINE = re.compile(r"expect-online:\s*([A-Z]+[0-9]+(?:\s*,\s*[A-Z]+[0-9]+)*)")


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def fake_values() -> Dict[str, str]:
    # Built at test time so that no credential-shaped string is ever committed to the repository.
    body = "".join("aB3dE5fG7hJ9kL2mN4pQ6rS8tU" for _ in range(4))
    return {
        "FAKE_OPENAI_KEY": "sk-" + "proj-" + body[:64],
        "FAKE_OPENAI_KEY2": "sk-" + "proj-" + body[3:67],
        "FAKE_OPENAI_KEY3": "sk-" + "proj-" + body[5:69],
        "FAKE_DB_PW": "Zq8" + "wX2vR7nP4tL9",
        "FAKE_SERVICE_ROLE_JWT": ".".join([
            _b64({"alg": "HS256", "typ": "JWT"}),
            _b64({"iss": "supabase", "ref": "abcdefghijklmnop", "role": "service_" + "role", "iat": 1700000000}),
            "Q2hhbmdlTWVQbGVhc2VUaGlzSXNOb3RBUmVhbFNpZ25hdHVyZQ",
        ]),
        "FAKE_GOOGLE_KEY": "AI" + "za" + "SyD8x7Kq2LmN4pR6tV8wX0zB2cE4gH6jK8m",
        "FAKE_PRIVATE_KEY": "-----BEGIN " + "PRIVATE KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, 96, 32))
                            + "\n-----END " + "PRIVATE KEY-----",
    }


def materialize(name: str, dest: Path, src: Path = None) -> Path:
    """Copy a sample app (a fixture by default) to dest, filling in {{FAKE_*}} placeholders."""
    src = src or FIXTURES / name
    target = dest / name
    shutil.copytree(src, target)
    values = fake_values()
    for path in target.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            new = re.sub(r"\{\{(FAKE_[A-Z0-9_]+)\}\}", lambda m: values[m.group(1)], text)
            if new != text:
                path.write_bytes(new.encode("utf-8"))
    return target


def expected(name: str, online: bool = False) -> Set[Tuple[str, int, str]]:
    out: Set[Tuple[str, int, str]] = set()
    root = FIXTURES / name
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for rx in (MARKER, MARKER_ONLINE) if online else (MARKER,):
                for m in rx.finditer(line):
                    for rule in m.group(1).split(","):
                        out.add((rel, i, rule.strip()))
    extra = FIXTURES / (name + ".expected")
    if extra.exists():
        for line in extra.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                rel, ln, rule = line.rsplit(":", 2)
                out.add((rel, int(ln), rule))
    return out


def actual(result) -> Set[Tuple[str, int, str]]:
    return {(f.file, f.line, f.rule_id) for f in result.findings}


def diff_message(exp, act) -> str:
    missing = sorted(exp - act)
    extra = sorted(act - exp)
    return "missing (expected but not found):\n  " + "\n  ".join(map(str, missing)) + \
        "\nunexpected (false alarms):\n  " + "\n  ".join(map(str, extra))
