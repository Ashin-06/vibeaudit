"""Build the public sample report (GitHub Pages) for the deliberately vulnerable fixture.

    python tools/sample_report.py _site

The fixture's `expect:` annotations (test bookkeeping) are stripped from the copy that is scanned, paths are shown
relative to the repository, and the pages say the app is vulnerable on purpose, so a score of 0/100 is expected."""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from helpers import materialize  # noqa: E402

EXPECT = re.compile(r"[ \t]*(?://|#|--)[ \t]*expect:[^\n]*|[ \t]*\(expect:[^)\n]*\)")
NOTE = ('<p class="muted"><b>This is a deliberately vulnerable demo app</b> (every finding is planted on purpose), '
        'so a score of 0/100 is expected.</p>')
FRAMEWORKS = ("owasp", "owasp-llm", "eu-ai-act", "soc2", "hipaa", "gdpr")


def main(out: str) -> None:
    site = Path(out)
    site.mkdir(parents=True, exist_ok=True)
    app = materialize("vuln_next_supabase", ROOT / "sample")
    for path in app.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            new = EXPECT.sub("", text)  # same line count, so finding lines still match the code
            if new != text:
                path.write_text(new, encoding="utf-8", newline="")
    args = [sys.executable, "-m", "vibeaudit", "scan", str(app.relative_to(ROOT)), "--offline", "--fail-on", "none",
            "-q", "-r", f"html:{site / 'index.html'}"]
    for fw in FRAMEWORKS:
        args += ["-r", f"compliance:{fw}:{site / f'compliance-{fw}.html'}"]
    subprocess.run(args, cwd=ROOT, check=True)
    for page in site.glob("*.html"):
        html = page.read_text(encoding="utf-8")
        html = html.replace(str(ROOT) + "/", "").replace(str(ROOT) + "\\", "").replace(str(ROOT), ".")
        html = re.sub(r"(</h1>)", r"\1" + NOTE.replace("\\", "\\\\"), html, count=1)
        page.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "_site")
