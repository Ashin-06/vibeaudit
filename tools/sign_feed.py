"""Build and sign the threat feed from src/vibeaudit/data/threat_data.json (run by .github/workflows/feed.yml).

    VIBEAUDIT_FEED_KEY='<private key JSON>' python tools/sign_feed.py OUT_FILE

The private key is read from the environment only, never from or to a file, and is never printed. The signed
feed is checked against the public key in the package before it is written, so a secret that does not match
the committed key fails here instead of publishing a feed no installation accepts.

With no key in the environment (before the one-time setup) it prints a notice, writes nothing and exits 0, so
the scheduled workflow stays green and publishes nothing. Any other problem exits 1.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from vibeaudit import feed  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    if not os.environ.get("VIBEAUDIT_FEED_KEY", "").strip():
        print("::notice::feed signing key not configured; see docs/THREAT_FEED.md")
        return 0
    try:
        key = json.loads(os.environ["VIBEAUDIT_FEED_KEY"])
        if not isinstance(key, dict) or not all(isinstance(key.get(k), str) for k in ("n", "d")):
            raise ValueError
    except ValueError:
        print("VIBEAUDIT_FEED_KEY is not a key made by tools/gen_feed_key.py", file=sys.stderr)
        return 1
    if feed.public_key() is None:
        print("src/vibeaudit/data/feed_key.json is missing: run tools/gen_feed_key.py first", file=sys.stderr)
        return 1
    try:
        raw = feed.build(feed.shipped(), key)
        doc = feed.open_feed(raw)
    except (ValueError, KeyError, TypeError):  # their messages can quote part of the key, so say only this
        print("VIBEAUDIT_FEED_KEY is not a key made by tools/gen_feed_key.py", file=sys.stderr)
        return 1
    except feed.FeedError as e:
        print(f"the feed could not be signed or does not verify against the committed public key: {e}", file=sys.stderr)
        return 1
    Path(sys.argv[1]).write_bytes(raw)
    d = doc["data"]
    print(f"signed feed version {doc['version']}, expires {doc['expires']}: {len(d.get('slopsquatted', []))} slopsquatted names, "
          f"{len(d.get('model_sunsets', []))} model sunsets, {len(d.get('prompt_injection', []))} injection patterns")
    return 0


if __name__ == "__main__":
    sys.exit(main())
