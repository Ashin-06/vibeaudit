"""Damaged input that used to end in a traceback: a forged bundle, a report path that cannot be written."""
import hashlib
import json
import struct
import subprocess
import sys
import zipfile

import pytest

from vibeaudit import bundle


def test_a_bundle_whose_zip_headers_lie_is_rejected(tmp_path):
    data = b"m-1\n" * 300_000
    path = tmp_path / "forged.zip"
    manifest = {"format": bundle.FORMAT, "files": {"data/retired_models.txt": {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}}}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest))
        z.writestr("data/retired_models.txt", data)
    raw = bytearray(path.read_bytes())
    central = raw.rfind(b"PK\x01\x02")
    struct.pack_into("<I", raw, central + 24, 100)  # declare 100 bytes: slips under the size cap, fails the CRC
    path.write_bytes(bytes(raw))
    with pytest.raises(bundle.BundleError, match="cannot be read"):
        bundle.import_bundle(path, lambda m: None)


def test_a_report_path_that_cannot_be_written_is_a_usage_error(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    blocker = tmp_path / "file.txt"
    blocker.write_text("in the way")
    run = subprocess.run([sys.executable, "-m", "vibeaudit", "scan", str(tmp_path), "--offline", "--external", "none", "-q",
                          "--fail-on", "none", "-r", f"json:{blocker / 'r.json'}"], capture_output=True, text=True)
    assert run.returncode == 2 and "cannot write the report" in run.stderr and "Traceback" not in run.stderr
