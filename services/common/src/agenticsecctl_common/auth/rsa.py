"""RS256 verification with the standard library only (RSASSA-PKCS1-v1_5, SHA-256, RFC 8017).

Verification is exact: the whole encoded message is rebuilt and compared in
constant time, so padding variants and trailing garbage cannot pass. The
product only verifies; it never holds or generates private keys.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
MIN_E = 65537


class KeysUnavailable(Exception):
    """The signing keys cannot be obtained or trusted; callers deny."""


@dataclass(frozen=True)
class RsaPublicKey:
    n: int
    e: int
    kid: str

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def usable(self) -> bool:
        return self.n > 0 and self.n % 2 == 1 and MIN_E <= self.e < 2**64 and self.e % 2 == 1


def verify_rs256(key: RsaPublicKey, message: bytes, signature: bytes) -> bool:
    if not key.usable:
        return False
    k = (key.n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= key.n:
        return False
    em = pow(s, key.e, key.n).to_bytes(k, "big")
    digest = _SHA256_PREFIX + hashlib.sha256(message).digest()
    if k < len(digest) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(digest) - 3) + b"\x00" + digest
    return hmac.compare_digest(em, expected)
