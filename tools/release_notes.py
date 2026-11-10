"""Print the CHANGELOG.md section of one version (the GitHub release notes).

    python tools/release_notes.py 0.6.0
Exits 1 when the version has no section, so a release cannot go out without its changelog entry.
"""
import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def section(version: str, text: str) -> str:
    m = re.search(r"^## \[%s\][^\n]*\n(.*?)(?=^## \[|\Z)" % re.escape(version), text, re.M | re.S)
    return m.group(1).strip() + "\n" if m else ""


def main() -> int:
    notes = section(sys.argv[1].lstrip("v"), CHANGELOG.read_text(encoding="utf-8"))
    if not notes:
        print(f"CHANGELOG.md has no section for {sys.argv[1]}", file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
