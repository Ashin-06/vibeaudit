"""Maintainer-only RSA key generation and signing helpers for the threat feed (not shipped in the wheel).

Tools and tests import key generation and feed signing from here so the runtime `vibeaudit` package
ships PKCS#1 v1.5 signature verification only.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import math
import secrets
from typing import Optional

from vibeaudit import feed


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


def _prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (3 << (bits - 2)) | 1  # top two bits set, so p * q has the full length
        if _probable_prime(c):
            return c


def generate_key(bits: int = 3072) -> dict:
    """A new RSA key pair as {"n", "e", "d"} (hex strings, e as an int). The public key is {"n", "e"}."""
    e = 65537
    while True:
        p, q = (_prime(bits // 2) for _ in range(2))
        phi = (p - 1) * (q - 1)
        if p != q and math.gcd(e, phi) == 1 and (p * q).bit_length() == bits:
            return {"n": format(p * q, "x"), "e": e, "d": format(pow(e, -1, phi), "x")}


def sign(message: bytes, key: dict) -> bytes:
    """Sign `message` with RSA PKCS#1 v1.5 SHA-256 using private key {"n", "d"}."""
    n, d = int(key["n"], 16), int(key["d"], 16)
    k = feed._size(n)
    return pow(int.from_bytes(feed._encoded(message, k), "big"), d, n).to_bytes(k, "big")


def build(data: dict, key: dict, now: Optional[dt.datetime] = None) -> bytes:
    """Build and sign a threat-feed JSON document for `data`."""
    now = now or dt.datetime.now(dt.timezone.utc)
    feed.check_data(data)
    payload = json.dumps({
        "format": feed.FORMAT, "version": int(now.timestamp()),
        "created": now.isoformat(timespec="seconds"),
        "expires": (now + dt.timedelta(days=feed.LIFETIME_DAYS)).isoformat(timespec="seconds"),
        "data": data,
    }, sort_keys=True)
    sig = base64.b64encode(sign(payload.encode("utf-8"), key)).decode("ascii")
    return (json.dumps({"payload": payload, "signature": sig}) + "\n").encode("utf-8")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(val)) + val


def _der_int(x: int) -> bytes:
    b = x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _der_tlv(0x02, b)


def public_key_to_pem(key: dict) -> bytes:
    """Encode an RSA public key {"n", "e"} as X.509 SubjectPublicKeyInfo PEM."""
    n, e = int(key["n"], 16), int(key["e"])
    rsa_pub = _der_tlv(0x30, _der_int(n) + _der_int(e))
    alg_id = bytes.fromhex("300d06092a864886f70d0101010500")  # rsaEncryption + NULL
    spki = _der_tlv(0x30, alg_id + _der_tlv(0x03, b"\x00" + rsa_pub))
    b64 = base64.b64encode(spki).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n").encode("ascii")
