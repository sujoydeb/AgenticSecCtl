"""WP-1.10 tests: token validation (FR-AUTHN-1, TC-F2, TC-G2) and key-set handling."""
import hashlib
import hmac
import http.server
import json
import threading
import unittest
from datetime import UTC, datetime, timedelta

from agenticsecctl_common.auth.jwks import JwksCache, guarded_fetcher
from agenticsecctl_common.auth.jwt import AuthError, TokenValidator
from agenticsecctl_common.auth.rsa import KeysUnavailable
from agenticsecctl_common.http import ExceptionEntry, Guard, GuardedClient
from rsa_helper import PREFIX, Key, b64, make_token

ISS, AUD = "https://idp.example.test/realms/dev", "https://gateway.example.test/mcp"
NOW = 1_800_000_000.0
KEY, OTHER = Key(2048, "k1"), Key(2048, "k1")  # same kid, different key material


def claims(**kw):
    c = {"iss": ISS, "aud": AUD, "sub": "svc-1", "azp": "agent-1", "iat": NOW - 10, "nbf": NOW - 10,
         "exp": NOW + 300, "scope": "mcp:call mcp:list"}
    c.update(kw)
    return {k: v for k, v in c.items() if v is not None}


class Source:
    def __init__(self, *keys):
        self.keys = {k.kid: k for k in keys}
        self.fail = False

    def get(self, kid):
        if self.fail:
            raise KeysUnavailable("down")
        k = self.keys.get(kid)
        return None if k is None else _pub(k)


def _pub(k):
    from agenticsecctl_common.auth.rsa import RsaPublicKey
    return RsaPublicKey(k.n, k.e, k.kid)


def validator(src=None, **kw):
    args = {"issuer": ISS, "audience": AUD, "keys": src or Source(KEY), "clock": lambda: NOW}
    args.update(kw)
    return TokenValidator(**args)


class Valid(unittest.TestCase):
    def test_good_token(self):
        c = validator().validate(make_token(KEY, claims()))
        self.assertEqual((c.subject, c.client_id, c.issuer), ("svc-1", "agent-1", ISS))
        self.assertEqual(c.scopes, frozenset({"mcp:call", "mcp:list"}))

    def test_audience_list_and_client_id_fallback(self):
        c = validator().validate(make_token(KEY, claims(aud=["x", AUD], azp=None, client_id="c9")))
        self.assertEqual(c.client_id, "c9")

    def test_required_scope(self):
        validator(required_scopes=("mcp:call",)).validate(make_token(KEY, claims()))


class Rejects(unittest.TestCase):
    def deny(self, token, reason, **kw):
        with self.assertRaises(AuthError) as cm:
            validator(**kw).validate(token)
        self.assertEqual(cm.exception.reason, reason, str(token)[:40])

    # algorithm and header attacks
    def test_alg_none(self):
        h = b64(b'{"alg":"none","kid":"k1"}'); p = b64(json.dumps(claims()).encode())
        self.deny(f"{h}.{p}.", "alg")
        self.deny(f"{h}.{p}.{b64(b'x')}", "alg")

    def test_hmac_with_public_key_as_secret(self):
        h = b64(json.dumps({"alg": "HS256", "kid": "k1"}).encode()); p = b64(json.dumps(claims()).encode())
        sig = hmac.new(KEY.n.to_bytes(KEY.k, "big"), f"{h}.{p}".encode(), hashlib.sha256).digest()
        self.deny(f"{h}.{p}.{b64(sig)}", "alg")

    def test_other_algs(self):
        for alg in ("RS384", "RS512", "PS256", "ES256", "EdDSA", "rs256", "", None, 5):
            self.deny(make_token(KEY, claims(), header={"alg": alg}), "alg")

    def test_header_tricks(self):
        for h in ({"jku": "https://evil/jwks"}, {"jwk": {"kty": "RSA"}}, {"x5u": "https://evil"},
                  {"crit": ["exp"]}, {"kid": None}, {"kid": 5}, {"kid": ""}):
            self.deny(make_token(KEY, claims(), header=h), "header")

    def test_missing_kid(self):
        h = b64(b'{"alg":"RS256"}'); p = b64(json.dumps(claims()).encode())
        self.deny(f"{h}.{p}.{b64(b'x' * 256)}", "header")

    def test_unknown_kid(self):
        self.deny(make_token(KEY, claims(), header={"kid": "nope"}), "kid")

    # structure
    def test_malformed(self):
        for t in ("", "a", "a.b", "a.b.c.d", "...", "a.b.c", "!!.!!.!!", " ", "a b.c.d"):
            self.deny(t, "malformed")
        self.deny("x" * 9000, "malformed")
        good = make_token(KEY, claims()).split(".")
        self.deny(f"{good[0]}.{b64(b'[1,2]')}.{good[2]}", "malformed")
        self.deny(f"{good[0]}.{b64(b'not json')}.{good[2]}", "malformed")
        self.deny(f"{b64(b'[]')}.{good[1]}.{good[2]}", "malformed")
        self.deny(good[0] + "." + good[1] + "=." + good[2], "malformed")  # padding not allowed

    def test_non_string_token(self):
        self.deny(None, "malformed")
        self.deny(b"abc", "malformed")

    # signature
    def test_tampered_payload(self):
        h, p, s = make_token(KEY, claims()).split(".")
        p2 = b64(json.dumps(claims(sub="admin")).encode())
        self.deny(f"{h}.{p2}.{s}", "signature")

    def test_wrong_key_same_kid(self):
        self.deny(make_token(KEY, claims(), sign_with=OTHER), "signature")

    def test_bad_signature_shapes(self):
        for sig in (b"", b"\x00" * 10, b"\x00" * KEY.k, b"\xff" * KEY.k, b"\x00" * (KEY.k + 1)):
            self.deny(make_token(KEY, claims(), sig=sig), "signature")

    def test_signature_not_below_modulus(self):
        s = (KEY.n + 5).to_bytes(KEY.k + 1, "big")
        self.deny(make_token(KEY, claims(), sig=s), "signature")

    def test_pkcs1_padding_malleability(self):
        # a valid signature over an encoding with trailing garbage, short padding or another digest must fail
        def em_variant(kind):
            def build(msg):
                h = PREFIX + hashlib.sha256(msg).digest()
                if kind == "trailing":
                    body = h + b"\x00junk"
                    return b"\x00\x01" + b"\xff" * (KEY.k - len(body) - 3) + b"\x00" + body
                if kind == "short-ff":
                    return b"\x00\x01" + b"\xff" * 8 + b"\x00" + h + b"\x00" * (KEY.k - len(h) - 11)
                if kind == "wrong-hash":
                    return b"\x00\x01" + b"\xff" * (KEY.k - len(h) - 3) + b"\x00" + PREFIX + hashlib.sha256(b"x").digest()
                if kind == "no-prefix":
                    d = hashlib.sha256(msg).digest()
                    return b"\x00\x01" + b"\xff" * (KEY.k - len(d) - 3) + b"\x00" + d
                if kind == "type2":
                    return b"\x00\x02" + b"\xff" * (KEY.k - len(h) - 3) + b"\x00" + h
            return build
        for kind in ("trailing", "short-ff", "wrong-hash", "no-prefix", "type2"):
            head = b64(json.dumps({"alg": "RS256", "kid": "k1"}).encode()); body = b64(json.dumps(claims()).encode())
            si = f"{head}.{body}".encode()
            sig = KEY.sign(si, em=em_variant(kind)(si))
            self.deny(f"{head}.{body}.{b64(sig)}", "signature")

    def test_small_exponent_key_refused(self):
        weak = Key(2048, "k1", e=3)
        self.deny(make_token(weak, claims()), "kid", keys=Source(weak))

    # claims
    def test_claims(self):
        for kw, reason in [
            ({"iss": "https://evil.test"}, "iss"), ({"iss": None}, "iss"), ({"iss": ISS + "/"}, "iss"),
            ({"aud": "https://other.test"}, "aud"), ({"aud": None}, "aud"), ({"aud": []}, "aud"),
            ({"aud": [AUD + "x"]}, "aud"), ({"aud": 5}, "aud"),
            ({"exp": NOW - 31}, "exp"), ({"exp": None}, "exp"), ({"exp": "soon"}, "exp"), ({"exp": True}, "exp"),
            ({"nbf": NOW + 100}, "nbf"), ({"iat": NOW + 100}, "iat"), ({"iat": None}, "iat"),
            ({"exp": NOW + 3600, "iat": NOW - 10}, "lifetime"),
            ({"sub": None}, "sub"), ({"sub": ""}, "sub"), ({"sub": 7}, "sub"),
            ({"azp": None}, "client"),
        ]:
            self.deny(make_token(KEY, claims(**kw)), reason)

    def test_expiry_boundary_and_leeway(self):
        validator(leeway=30).validate(make_token(KEY, claims(exp=NOW - 29)))
        self.deny(make_token(KEY, claims(exp=NOW - 1)), "exp", leeway=0)
        self.deny(make_token(KEY, claims(exp=NOW)), "exp", leeway=0)

    def test_scope(self):
        self.deny(make_token(KEY, claims(scope="mcp:list")), "scope", required_scopes=("mcp:call",))
        self.deny(make_token(KEY, claims(scope=None)), "scope", required_scopes=("mcp:call",))

    def test_reasons_never_echo_input(self):
        with self.assertRaises(AuthError) as cm:
            validator().validate(make_token(KEY, claims(iss="https://SECRET-MARKER.test")))
        self.assertNotIn("SECRET-MARKER", str(cm.exception))


class Keys(unittest.TestCase):
    def doc(self, *keys, **extra):
        return json.dumps({"keys": [k.jwk() if hasattr(k, "jwk") else k for k in keys], **extra}).encode()

    def cache(self, fetch, **kw):
        t = {"now": NOW}
        c = JwksCache("https://idp.example.test/jwks", fetch, clock=lambda: t["now"], **kw)
        return c, t

    def test_fetch_failure_with_no_cache_denies(self):
        def boom(url):
            raise OSError("down")
        c, _ = self.cache(boom)
        with self.assertRaises(KeysUnavailable):
            c.get("k1")
        with self.assertRaises(AuthError) as cm:
            validator(c).validate(make_token(KEY, claims()))
        self.assertEqual(cm.exception.reason, "keys-unavailable")

    def test_fetch_failure_after_cache_expiry_denies_but_within_ttl_works(self):
        state = {"up": True}
        def fetch(url):
            if not state["up"]:
                raise OSError("down")
            return self.doc(KEY)
        c, t = self.cache(fetch, ttl=300)
        v = validator(c)
        v.validate(make_token(KEY, claims()))
        state["up"] = False
        t["now"] = NOW + 299
        validator(c, clock=lambda: t["now"]).validate(make_token(KEY, claims(exp=NOW + 400, iat=NOW + 290, nbf=NOW + 290)))
        t["now"] = NOW + 301
        with self.assertRaises(KeysUnavailable):
            c.get("k1")

    def test_rotation_new_kid_triggers_one_refresh_throttled(self):
        k2 = Key(2048, "k2")
        calls = []
        docs = [self.doc(KEY), self.doc(KEY, k2)]
        def fetch(url):
            calls.append(url)
            return docs[min(len(calls) - 1, 1)]
        c, t = self.cache(fetch, ttl=3600, min_refresh_interval=30)
        self.assertIsNotNone(c.get("k1"))
        t["now"] = NOW + 31
        self.assertIsNotNone(c.get("k2"))
        self.assertEqual(len(calls), 2)
        self.assertIsNone(c.get("unknown")); self.assertIsNone(c.get("unknown2"))
        self.assertEqual(len(calls), 2, "unknown kids must not hammer the key endpoint")

    def test_removed_key_disappears_after_refresh(self):
        docs = [self.doc(KEY), self.doc(Key(2048, "k2"))]
        n = {"i": 0}
        def fetch(url):
            d = docs[min(n["i"], 1)]; n["i"] += 1; return d
        c, t = self.cache(fetch, ttl=100)
        self.assertIsNotNone(c.get("k1"))
        t["now"] = NOW + 101
        self.assertIsNone(c.get("k1"))

    def test_bad_documents_are_failures(self):
        for body in (b"", b"not json", b"[]", b'{"keys": "x"}', b'{}', b'{"keys": []}'):
            c, _ = self.cache(lambda u, b=body: b)
            with self.assertRaises(KeysUnavailable):
                c.get("k1")

    def test_only_usable_rsa_keys_are_kept(self):
        small = Key(1024, "small")
        junk = [{"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"},
                {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
                {"kty": "RSA", "kid": "noalg", "alg": "RS512", "n": "AQAB", "e": "AQAB"},
                {"kty": "RSA", "n": "AQAB", "e": "AQAB"}, small.jwk()]
        c, _ = self.cache(lambda u: self.doc(KEY, *junk))
        self.assertIsNotNone(c.get("k1"))
        for kid in ("ec", "enc", "noalg", "small"):
            self.assertIsNone(c.get(kid), kid)

    def test_duplicate_kid_is_refused(self):
        c, _ = self.cache(lambda u: self.doc(KEY, OTHER))
        with self.assertRaises(KeysUnavailable):
            c.get("k1")

    def test_discovery_issuer_mismatch_and_scheme(self):
        disc = lambda iss, jwks: json.dumps({"issuer": iss, "jwks_uri": jwks}).encode()
        urls = []
        def fetch(url):
            urls.append(url)
            return {"https://idp.example.test/realms/dev/.well-known/openid-configuration":
                    disc(ISS, "https://idp.example.test/certs")}.get(url) or self.doc(KEY)
        c = JwksCache.from_discovery(ISS, fetch, clock=lambda: NOW)
        self.assertIsNotNone(c.get("k1"))
        self.assertEqual(urls[-1], "https://idp.example.test/certs")
        for bad in (disc("https://evil.test", "https://idp.example.test/certs"),
                    disc(ISS, "http://idp.example.test/certs"), disc(ISS, "file:///etc/passwd"), b"{}"):
            c = JwksCache.from_discovery(ISS, lambda u, b=bad: b, clock=lambda: NOW)
            with self.assertRaises(KeysUnavailable):
                c.get("k1")

    def test_http_allowed_only_when_asked(self):
        c = JwksCache.from_discovery("http://idp.local/realms/dev", lambda u: b"{}", clock=lambda: NOW)
        with self.assertRaises(KeysUnavailable):
            c.get("k1")


class _IdP(http.server.BaseHTTPRequestHandler):
    log_message = lambda *a, **k: None
    keys = []

    def do_GET(self):
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        if self.path.endswith("openid-configuration"):
            body = json.dumps({"issuer": base + "/realms/dev", "jwks_uri": base + "/certs"}).encode()
        elif self.path == "/certs":
            body = json.dumps({"keys": [k.jwk() for k in _IdP.keys]}).encode()
        else:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


class GuardedIdentityFetch(unittest.TestCase):
    """The identity provider is a private address: refused without an exception entry, allowed with one,
    refused again after the entry expires (WP-1.3 and WP-1.10 tests-first item, IG-4)."""

    @classmethod
    def setUpClass(cls):
        _IdP.keys = [KEY]
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _IdP)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.iss = f"http://127.0.0.1:{cls.port}/realms/dev"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def cache(self, entries, now):
        guard = Guard(resolver=lambda h, p: [], exceptions=tuple(entries), environment="development", clock=lambda: now)
        return JwksCache.from_discovery(self.iss, guarded_fetcher(GuardedClient(guard)), allow_http=True, clock=lambda: NOW)

    def entry(self, expires):
        return ExceptionEntry(host="127.0.0.1", port=self.port, owner="security-engineer", reason="development Keycloak",
                              expires_at=expires, environments=frozenset({"development"}))

    def test_refused_without_exception(self):
        now = datetime(2026, 11, 23, tzinfo=UTC)
        with self.assertRaises(KeysUnavailable):
            self.cache([], now).get("k1")

    def test_allowed_with_exception_and_validates_a_token(self):
        now = datetime(2026, 11, 23, tzinfo=UTC)
        c = self.cache([self.entry(now + timedelta(days=1))], now)
        v = TokenValidator(issuer=self.iss, audience=AUD, keys=c, clock=lambda: NOW)
        v.validate(make_token(KEY, claims(iss=self.iss)))

    def test_refused_again_after_expiry(self):
        now = datetime(2026, 11, 23, tzinfo=UTC)
        with self.assertRaises(KeysUnavailable):
            self.cache([self.entry(now - timedelta(seconds=1))], now).get("k1")


if __name__ == "__main__":
    unittest.main()
