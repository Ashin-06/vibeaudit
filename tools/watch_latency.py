"""Measure `vibeaudit watch` re-scan latency on a benchmark repository, and check every incremental result
against a fresh full scan.

A copy of the repository (without .git) gets a series of single-file edits to each of the N largest source
files in turn: append a comment, add a hard-coded key (a new finding), remove it again. After each edit the kept Project is refreshed and re-scanned; the time is
recorded and the findings are compared with a cold scan of the same tree.

    python tools/watch_latency.py NAME [--edits 10]
"""
from __future__ import annotations

import argparse
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from benchmark import checkout_path, corpus  # noqa: E402
from vibeaudit.files import Project  # noqa: E402
from vibeaudit.guard import StepMemo  # noqa: E402
from vibeaudit.scanner import Options, scan  # noqa: E402

COMMENT = {".py": "\n# edited\n", ".js": "\n// edited\n", ".ts": "\n// edited\n", ".tsx": "\n// edited\n", ".jsx": "\n// edited\n"}


def options() -> Options:
    return Options(offline=True, external="none", feedback=False, cache=False, min_severity="low", include_preview=True)


def keyset(res):
    return sorted((f.rule_id, f.file, f.line, f.message) for f in res.findings)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--edits", type=int, default=10)
    ap.add_argument("--lsp", action="store_true",
                    help="edit through the language server (unsaved buffers, didChange) instead of on disk")
    a = ap.parse_args(argv)
    repo = next(r for r in corpus() if r["name"] == a.name)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / a.name
        shutil.copytree(checkout_path(repo), root, ignore=shutil.ignore_patterns(".git"))
        t = time.perf_counter()
        cold = scan(str(root), options())
        cold_s = time.perf_counter() - t
        project = Project(root)
        project.step_memo = StepMemo()
        scan(str(root), options(), project)
        t = time.perf_counter()
        project.refresh()
        scan(str(root), options(), project)
        idle_s = time.perf_counter() - t
        files = sorted((p for p in root.rglob("*") if p.suffix in COMMENT and "node_modules" not in p.parts),
                       key=lambda p: -p.stat().st_size)[:a.edits]
        times, mismatches = [], 0
        server = None
        if a.lsp:
            import io

            from vibeaudit import lsp

            server = lsp.Server(io.BytesIO())
            server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"rootUri": root.as_uri()}})
            server.scan()
        key = "API_KEY = " + repr("q8Zr" + "Lw2Xv9Tn4Pk7Hs1Jd6Fy3Bm5Gc0")  # built here: no secret-shaped literal in the repo
        steps = []
        for p in files:  # per file: add a comment, add a hard-coded key (a new finding), then remove the key again
            original = p.read_text(encoding="utf-8", errors="replace")
            steps += [(p, original + COMMENT[p.suffix]),
                      (p, original + COMMENT[p.suffix] + ("const " if p.suffix != ".py" else "") + key + "\n"),
                      (p, original + COMMENT[p.suffix])]
        for p, text in steps:
            if server is not None:
                rel = p.relative_to(root).as_posix()
                method = "textDocument/didChange" if rel in server.docs else "textDocument/didOpen"
                server.handle({"jsonrpc": "2.0", "method": method, "params": {
                    "textDocument": {"uri": p.as_uri(), "version": 1, "text": text}, "contentChanges": [{"text": text}]}})
                t = time.perf_counter()
                server.scan()
                times.append(time.perf_counter() - t)
                got = sorted((f.rule_id, f.file, f.line, f.message) for fs in server.findings.values() for f in fs)
                p.write_text(text, encoding="utf-8")  # the same content on disk, for the fresh scan
                if got != keyset(scan(str(root), server.watcher.opts)):
                    mismatches += 1
                    print(f"MISMATCH after editing {rel} in the language server", file=sys.stderr)
                continue
            p.write_text(text, encoding="utf-8")
            t = time.perf_counter()
            changed = project.refresh()
            warm = scan(str(root), options(), project)
            times.append(time.perf_counter() - t)
            fresh = scan(str(root), options())
            if keyset(warm) != keyset(fresh):
                mismatches += 1
                print(f"MISMATCH after editing {p.relative_to(root)}", file=sys.stderr)
            assert p.relative_to(root).as_posix() in changed, changed
        print(f"{a.name}: {cold.meta['files_scanned']} files, {len(cold.findings)} findings")
        print(f"cold scan {cold_s * 1000:.0f} ms; re-scan with no change {idle_s * 1000:.0f} ms")
        if times:
            print(f"{'language server ' if a.lsp else ''}re-scan after one edit: median {statistics.median(times) * 1000:.0f} ms, "
                  f"max {max(times) * 1000:.0f} ms over {len(times)} edits of {len(files)} files; mismatches with a fresh scan: {mismatches}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
