"""Generate the threat feed's signing key pair (one-time setup, run by a maintainer on their own machine).

    python tools/gen_feed_key.py PRIVATE_KEY_FILE [--force]

Writes the private key to PRIVATE_KEY_FILE (which must be outside this repository) and the public key to
src/vibeaudit/data/feed_key.json, which is committed and ships with the package. Then put the private key into
the repository secret and delete the file (or keep it offline). Steps: docs/THREAT_FEED.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from vibeaudit.feed import generate_key  # noqa: E402

PUBLIC = ROOT / "src" / "vibeaudit" / "data" / "feed_key.json"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("private_key_file")
    ap.add_argument("--force", action="store_true", help="replace an existing key (installed copies then use their shipped data until they upgrade)")
    a = ap.parse_args()
    private = Path(a.private_key_file).resolve()
    if private == ROOT or ROOT in private.parents:
        print("the private key file must be outside the repository, so it cannot be committed", file=sys.stderr)
        return 2
    if private.exists() or (PUBLIC.exists() and not a.force):
        print(f"{private if private.exists() else PUBLIC} already exists (use --force to replace the public key)", file=sys.stderr)
        return 2
    key = generate_key()
    fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        json.dump(key, f)
    public = {"n": key["n"], "e": key["e"]}
    PUBLIC.write_text(json.dumps(public, indent=1) + "\n", encoding="ascii", newline="\n")
    print(f"private key: {private} (put it into the VIBEAUDIT_FEED_KEY secret, then delete this file)")
    print(f"public key:  {PUBLIC.relative_to(ROOT)} (commit it)")
    print(json.dumps(public, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
