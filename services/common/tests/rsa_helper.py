"""Test-only RSA key generation and RS256 signing (pure Python; the product only verifies)."""
import base64
import hashlib
import json
import secrets

_SMALL = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** .5) + 1, 2))]
PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _mr(n, k=12):
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if not any(c % p == 0 for p in _SMALL) and _mr(c):
            return c


class Key:
    def __init__(self, bits=2048, kid="k1", e=65537):
        while True:
            p, q = _prime(bits // 2), _prime(bits // 2)
            phi = (p - 1) * (q - 1)
            if p != q and phi % e:
                break
        self.n, self.e, self.d, self.kid = p * q, e, pow(e, -1, phi), kid
        self.k = (self.n.bit_length() + 7) // 8

    def jwk(self, **extra):
        b = lambda i: b64(i.to_bytes((i.bit_length() + 7) // 8, "big"))
        return {"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256", "n": b(self.n), "e": b(self.e), **extra}

    def em(self, msg, pad=None):
        h = PREFIX + hashlib.sha256(msg).digest()
        return b"\x00\x01" + b"\xff" * (self.k - len(h) - 3) + b"\x00" + h

    def sign(self, msg, em=None):
        em = em if em is not None else self.em(msg)
        return pow(int.from_bytes(em, "big"), self.d, self.n).to_bytes(self.k, "big")


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_token(key, claims, header=None, sign_with=None, em=None, sig=None):
    h = {"alg": "RS256", "typ": "at+jwt", "kid": key.kid}
    h.update(header or {})
    head = b64(json.dumps(h).encode())
    body = b64(json.dumps(claims).encode())
    signing_input = f"{head}.{body}".encode()
    signature = sig if sig is not None else (sign_with or key).sign(signing_input, em=em)
    return f"{head}.{body}.{b64(signature)}"
