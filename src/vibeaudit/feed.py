"""The signed threat-intel feed: slopsquatted package names (DEP001), a model sunset calendar (LLM012) and
prompt-injection patterns for agent instruction files (LLM019).

The data ships with the package (data/threat_data.json), so every check works offline. `vibeaudit update`
also downloads threat_feed.json, which a scheduled workflow builds from the same file on main and signs daily:

    {"payload": "<JSON text>", "signature": "<base64 RSA PKCS#1 v1.5 SHA-256 over the payload's UTF-8 bytes>"}

The payload holds a format, a version (seconds since the epoch, never decreasing), created and expires times
and the data. A feed is used only when its signature verifies against the public key shipped with the
package (data/feed_key.json) and it has not expired; otherwise vibeaudit warns and uses the shipped data.
Verification uses the standard library only. See docs/THREAT_FEED.md.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import math
import re
import secrets
import sys
from importlib import resources
from typing import Dict, List, Optional, Tuple

from .bundle import norm
from .store import cache_dir

FEED = "threat_feed.json"
FORMAT = 1
LIFETIME_DAYS = 30
ECOSYSTEMS = ("PyPI", "npm")
PACKAGE_NAME = re.compile(r"(?i)[@a-z0-9][\w.@/-]{0,213}")
MODEL_ID = re.compile(r"(?i)[a-z0-9][a-z0-9.@:_-]{1,80}\*?")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
# DER prefix of a SHA-256 DigestInfo (RFC 8017, section 9.2)
SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


class FeedError(Exception):
    pass


# ------------------------------------------------------------------ RSA (stdlib)
def _encoded(message: bytes, k: int) -> bytes:
    t = SHA256_INFO + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        raise FeedError("the key is too short")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def _size(n: int) -> int:
    return (n.bit_length() + 7) // 8


def sign(message: bytes, key: dict) -> bytes:
    n, d = int(key["n"], 16), int(key["d"], 16)
    k = _size(n)
    return pow(int.from_bytes(_encoded(message, k), "big"), d, n).to_bytes(k, "big")


def verify(message: bytes, signature: bytes, key: dict) -> bool:
    """Recompute the whole encoded block and compare it, rather than parsing the decrypted one."""
    n, e = int(key["n"], 16), int(key["e"])
    k = _size(n)
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    return s < n and hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), _encoded(message, k))


def _probable_prime(n: int) -> bool:
    for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(40):  # Miller-Rabin
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_key(bits: int = 3072) -> dict:
    """A new RSA key pair as {"n", "e", "d"} (hex strings, e as an int). The public key is {"n", "e"}."""
    e = 65537
    while True:
        p, q = (_prime(bits // 2) for _ in range(2))
        phi = (p - 1) * (q - 1)
        if p != q and math.gcd(e, phi) == 1 and (p * q).bit_length() == bits:
            return {"n": format(p * q, "x"), "e": e, "d": format(pow(e, -1, phi), "x")}


def _prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (3 << (bits - 2)) | 1  # top two bits set, so p * q has the full length
        if _probable_prime(c):
            return c


# ------------------------------------------------------------------ the feed file
def public_key() -> Optional[dict]:
    try:
        key = json.loads(resources.files("vibeaudit").joinpath("data", "feed_key.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None  # a build made before the key was set up: only the shipped data is used
    return key if isinstance(key, dict) and isinstance(key.get("n"), str) and isinstance(key.get("e"), int) else None


def build(data: dict, key: dict, now: Optional[dt.datetime] = None) -> bytes:
    """The signed feed for `data` (used by tools/sign_feed.py and the tests)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    check_data(data)
    payload = json.dumps({"format": FORMAT, "version": int(now.timestamp()),
                          "created": now.isoformat(timespec="seconds"),
                          "expires": (now + dt.timedelta(days=LIFETIME_DAYS)).isoformat(timespec="seconds"),
                          "data": data}, sort_keys=True)
    sig = base64.b64encode(sign(payload.encode("utf-8"), key)).decode("ascii")
    return (json.dumps({"payload": payload, "signature": sig}) + "\n").encode("utf-8")


def open_feed(raw: bytes, key: Optional[dict] = None) -> dict:
    """The payload of a signed feed. Raises FeedError when the signature or the contents are not valid;
    expiry is checked separately (expired())."""
    key = key or public_key()
    if key is None:
        raise FeedError("this copy of vibeaudit has no feed key")
    try:
        outer = json.loads(raw)
        payload, sig = outer["payload"], base64.b64decode(outer["signature"], validate=True)
    except (ValueError, KeyError, TypeError):
        raise FeedError("not a signed feed") from None
    if not isinstance(payload, str) or not verify(payload.encode("utf-8"), sig, key):
        raise FeedError("the signature does not match")
    try:
        doc = json.loads(payload)
        if doc["format"] != FORMAT or not isinstance(doc["version"], int):
            raise FeedError(f"unknown feed format {doc['format']!r}")
        _when(doc["expires"])
        check_data(doc["data"])
    except (ValueError, KeyError, TypeError) as e:
        raise FeedError(f"the feed's contents are not valid ({e})") from None
    return doc


def _when(stamp: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(stamp)
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def expired(doc: dict, now: Optional[dt.datetime] = None) -> bool:
    return _when(doc["expires"]) <= (now or dt.datetime.now(dt.timezone.utc))


def check_data(data: dict) -> None:
    """Raise FeedError (or ValueError) unless every entry is well formed and every pattern compiles."""
    if not isinstance(data, dict):
        raise FeedError("the data is not an object")

    def entries(name: str, fields: Tuple[str, ...]) -> List[dict]:
        items = data.get(name, [])
        if not isinstance(items, list) or not all(isinstance(e, dict) and all(isinstance(e.get(f), str) and e[f] for f in fields)
                                                  for e in items):
            raise FeedError(f"{name}: every entry needs {', '.join(fields)}")
        return items

    for e in entries("slopsquatted", ("ecosystem", "name", "note", "source")):
        if e["ecosystem"] not in ECOSYSTEMS or not PACKAGE_NAME.fullmatch(e["name"]):
            raise FeedError(f"slopsquatted: bad entry {e['ecosystem']}/{e['name']}")
    for e in entries("model_sunsets", ("id", "date", "source")):
        if not MODEL_ID.fullmatch(e["id"]) or not DATE.fullmatch(e["date"]):
            raise FeedError(f"model_sunsets: bad entry {e['id']} {e['date']}")
        dt.date.fromisoformat(e["date"])
    for e in entries("prompt_injection", ("id", "pattern", "description", "source")):
        try:
            re.compile(e["pattern"])
        except re.error as err:
            raise FeedError(f"prompt_injection: {e['id']} does not compile ({err})") from None


# ------------------------------------------------------------------ loading
_LOADED: List[dict] = []
_WARNED: set = set()


def _warn(msg: str) -> None:
    if msg not in _WARNED:
        _WARNED.add(msg)
        print(f"vibeaudit: warning: {msg}", file=sys.stderr)


def shipped() -> dict:
    return json.loads(resources.files("vibeaudit").joinpath("data", "threat_data.json").read_text(encoding="utf-8"))


def cached() -> Optional[dict]:
    """The installed feed's payload when it verifies and has not expired; warns about one that does not."""
    path = cache_dir() / "data" / FEED
    if not path.is_file():  # only after `vibeaudit update` or a bundle import
        return None
    try:
        doc = open_feed(path.read_bytes())
    except (OSError, FeedError) as e:
        _warn(f"the threat feed {path} was not used ({e}); using the threat data shipped with vibeaudit")
        return None
    if expired(doc):
        _warn(f"the threat feed {path} expired on {doc['expires'][:10]}; using the threat data shipped with "
              "vibeaudit (run `vibeaudit update`, or import a newer bundle)")
        return None
    return doc


def data() -> dict:
    """The shipped data with the installed feed's entries added (a feed entry replaces a shipped one with the
    same key, so a newer date or note wins)."""
    if not _LOADED:
        merged = shipped()
        doc = cached()
        if doc is not None:
            for name, key in (("slopsquatted", ("ecosystem", "name")), ("model_sunsets", ("id",)), ("prompt_injection", ("id",))):
                by_key = {tuple(e[k] for k in key): e for e in merged.get(name, []) + doc["data"].get(name, [])}
                merged[name] = list(by_key.values())
        _LOADED.append(merged)
    return _LOADED[0]


def slopsquatted() -> Dict[Tuple[str, str], dict]:
    return {(e["ecosystem"], norm(e["name"], e["ecosystem"])): e for e in data().get("slopsquatted", [])}


def sunsets() -> Dict[str, dict]:
    return {e["id"]: e for e in data().get("model_sunsets", [])}


_PATTERNS: List[List[Tuple[dict, "re.Pattern[str]"]]] = []


def injection_patterns() -> List[Tuple[dict, "re.Pattern[str]"]]:
    if not _PATTERNS:
        _PATTERNS.append([(e, re.compile(e["pattern"])) for e in data().get("prompt_injection", [])])
    return _PATTERNS[0]


def forget() -> None:
    _LOADED.clear()
    _PATTERNS.clear()
