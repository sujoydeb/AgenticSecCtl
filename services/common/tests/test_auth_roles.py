"""WP-1.10 tests: principals, role bindings and the endpoint role table (FR-ID-1/2, CTL-23, SoD)."""
import itertools
import pathlib
import re
import unittest
from datetime import UTC, datetime, timedelta

from agenticsecctl_common.auth.jwt import Claims
from agenticsecctl_common.auth.principals import (
    IdentityDirectory,
    IdentityError,
    Kind,
    Principal,
)
from agenticsecctl_common.auth.roles import (
    ENDPOINTS,
    INTERNAL_ENDPOINTS,
    Forbidden,
    Role,
    RoleBinding,
    RoleBindings,
    authorize,
)

NOW = datetime(2026, 11, 23, 12, tzinfo=UTC)
T1, T2 = "tenant-1", "tenant-2"
ROOT = pathlib.Path(__file__).resolve().parents[3]


def claims(client="dash", sub="alice", amr=("pwd", "otp"), tenant=T1, **extra):
    raw = {"azp": client, "sub": sub, "tenant_id": tenant, "amr": list(amr)}
    raw.update(extra)
    return Claims(sub, "iss", ("aud",), client, frozenset(), 0, 1, raw)


def directory():
    d = IdentityDirectory(user_clients={"dashboard"})
    d.register_user(T1, "alice", user_id="u-alice")
    d.register_user(T1, "amir", user_id="u-amir")
    d.register_user(T2, "alice", user_id="u-alice2")  # same subject, other tenant
    d.register_agent(T1, "agent-client-1", "agent-1")
    d.register_agent(T1, "agent-client-2", "agent-2")
    d.register_service("scanner-worker", "scanner")
    d.register_service("gateway-service", "gateway")
    return d


class Principals(unittest.TestCase):
    def test_user(self):
        p = directory().resolve(claims("dashboard", "alice"))
        self.assertEqual((p.kind, p.user_id, p.tenant), (Kind.USER, "u-alice", T1))

    def test_same_subject_in_two_tenants_resolves_by_tenant_claim(self):
        self.assertEqual(directory().resolve(claims("dashboard", "alice", tenant=T2)).user_id, "u-alice2")

    def test_user_without_mfa_refused(self):
        for amr in ((), ("pwd",), ("sms",)):
            with self.assertRaises(IdentityError) as cm:
                directory().resolve(claims("dashboard", "alice", amr=amr))
            self.assertEqual(cm.exception.reason, "mfa-required")

    def test_user_amr_missing_or_wrong_type(self):
        c = claims("dashboard", "alice"); c.raw["amr"] = "otp"
        with self.assertRaises(IdentityError):
            directory().resolve(c)
        del c.raw["amr"]
        with self.assertRaises(IdentityError):
            directory().resolve(c)

    def test_unknown_user_and_unknown_tenant(self):
        for c in (claims("dashboard", "mallory"), claims("dashboard", "alice", tenant="tenant-9"),
                  claims("dashboard", "alice", tenant=None), claims("dashboard", "alice", tenant=5)):
            with self.assertRaises(IdentityError):
                directory().resolve(c)

    def test_agent(self):
        p = directory().resolve(claims("agent-client-1", "svc-a1", amr=()))
        self.assertEqual((p.kind, p.agent_id, p.tenant, p.user_id), (Kind.AGENT, "agent-1", T1, None))

    def test_agent_tenant_comes_from_registration_not_the_token(self):
        p = directory().resolve(claims("agent-client-1", "svc-a1", amr=(), tenant=T2))
        self.assertEqual(p.tenant, T1)

    def test_unknown_client(self):
        with self.assertRaises(IdentityError) as cm:
            directory().resolve(claims("rogue-client"))
        self.assertEqual(cm.exception.reason, "unknown-client")

    def test_services(self):
        s = directory().resolve(claims("scanner-worker", "svc-s", amr=()))
        g = directory().resolve(claims("gateway-service", "svc-g", amr=()))
        self.assertEqual((s.kind, s.service, g.service), (Kind.SERVICE, "scanner", "gateway"))
        self.assertIsNone(s.tenant)

    def test_shared_credentials_between_agents_are_rejected(self):
        d = directory()
        with self.assertRaises(IdentityError):
            d.register_agent(T1, "agent-client-1", "agent-3")      # one client, two agents
        with self.assertRaises(IdentityError):
            d.register_agent(T2, "agent-client-1", "agent-9")      # same client in another tenant
        with self.assertRaises(IdentityError):
            d.register_agent(T1, "agent-client-3", "agent-1")      # a second client for one agent
        d.register_agent(T1, "agent-client-1", "agent-1")          # idempotent repeat is fine

    def test_client_roles_cannot_overlap(self):
        for first, second in itertools.permutations(("agent", "service", "user"), 2):
            d2 = IdentityDirectory()
            def reg(kind, name):
                if kind == "agent": d2.register_agent(T1, name, "x-" + name)
                elif kind == "service": d2.register_service(name, "scanner")
                else: d2.register_user_client(name)
            reg(first, "shared")
            with self.assertRaises(IdentityError, msg=f"{first} then {second}"):
                reg(second, "shared")

    def test_scanner_and_gateway_have_distinct_clients(self):
        d = directory()
        with self.assertRaises(IdentityError):
            d.register_service("scanner-worker", "gateway")
        with self.assertRaises(IdentityError):
            d.register_service("another", "scanner")  # one client per service role

    def test_agent_token_never_gets_user_privileges(self):
        p = directory().resolve(claims("agent-client-1", "alice", amr=("pwd", "otp")))
        self.assertEqual(p.kind, Kind.AGENT)
        self.assertIsNone(p.user_id)


def bindings(*rows):
    b = RoleBindings()
    for r in rows:
        b.add(r)
    return b


def user(uid="u-alice", tenant=T1):
    return directory().resolve(claims("dashboard", "alice" if uid == "u-alice" else "amir", tenant=tenant))


class Authorization(unittest.TestCase):
    def go(self, principal, method, path, store, **kw):
        return authorize(principal, method, path, store, now=NOW, **kw)

    def test_health_is_public(self):
        self.go(None, "GET", "/health", RoleBindings())

    def test_no_binding_no_access(self):
        with self.assertRaises(Forbidden):
            self.go(user(), "GET", "/agents", RoleBindings())

    def test_role_grants_listed_endpoints_only(self):
        store = bindings(RoleBinding(T1, "u-alice", Role.VIEWER))
        self.go(user(), "GET", "/agents", store)
        for m, p in (("POST", "/agents"), ("POST", "/approvals/{id}/decision"), ("PUT", "/tools/{id}/quarantine"),
                     ("GET", "/audit/events"), ("DELETE", "/agents/{id}/suspension")):
            with self.assertRaises(Forbidden, msg=f"{m} {p}"):
                self.go(user(), m, p, store)

    def test_every_endpoint_refuses_every_role_not_listed(self):
        for ep in ENDPOINTS:
            if ep.public:
                continue
            for role in Role:
                store = bindings(RoleBinding(T1, "u-alice", role))
                if role in ep.roles:
                    self.go(user(), ep.method, ep.path, store)
                else:
                    with self.assertRaises(Forbidden, msg=f"{role} on {ep.method} {ep.path}"):
                        self.go(user(), ep.method, ep.path, store)

    def test_unknown_endpoint_and_method_denied(self):
        store = bindings(*[RoleBinding(T1, "u-alice", r) for r in Role])
        for m, p in (("GET", "/nope"), ("PATCH", "/agents"), ("GET", "/agents/{id}/secrets"), ("POST", "/health")):
            with self.assertRaises(Forbidden):
                self.go(user(), m, p, store)

    def test_expired_binding_does_not_count(self):
        past = RoleBinding(T1, "u-alice", Role.VIEWER, expires_at=NOW - timedelta(seconds=1))
        exactly = RoleBinding(T1, "u-alice", Role.VIEWER, expires_at=NOW)
        live = RoleBinding(T1, "u-alice", Role.VIEWER, expires_at=NOW + timedelta(hours=1))
        for b in (past, exactly):
            with self.assertRaises(Forbidden):
                self.go(user(), "GET", "/agents", bindings(b))
        self.go(user(), "GET", "/agents", bindings(live))

    def test_bindings_do_not_cross_tenants_or_users(self):
        with self.assertRaises(Forbidden):
            self.go(user(), "GET", "/agents", bindings(RoleBinding(T2, "u-alice", Role.VIEWER)))
        with self.assertRaises(Forbidden):
            self.go(user(), "GET", "/agents", bindings(RoleBinding(T1, "u-amir", Role.VIEWER)))
        # the same subject in tenant 2 has its own user id and binding
        self.go(user(tenant=T2), "GET", "/agents", bindings(RoleBinding(T2, "u-alice2", Role.VIEWER)))

    def test_resource_scoped_binding_applies_to_that_resource_only(self):
        store = bindings(RoleBinding(T1, "u-alice", Role.AGENT_OWNER, scope=("agent", "agent-1")))
        self.go(user(), "GET", "/agents/{id}", store, resource=("agent", "agent-1"))
        with self.assertRaises(Forbidden):
            self.go(user(), "GET", "/agents/{id}", store, resource=("agent", "agent-2"))
        with self.assertRaises(Forbidden):
            self.go(user(), "GET", "/agents/{id}", store)  # no resource given
        with self.assertRaises(Forbidden):
            self.go(user(), "GET", "/agents/{id}", store, resource=("server", "agent-1"))
        with self.assertRaises(Forbidden):
            self.go(user(), "POST", "/agents", store)  # registering needs a tenant-wide owner binding

    def test_agent_principal_has_no_management_access(self):
        store = bindings(*[RoleBinding(T1, "agent-1", r) for r in Role])
        p = directory().resolve(claims("agent-client-1", "svc", amr=()))
        for ep in ENDPOINTS:
            if ep.public:
                continue
            with self.assertRaises(Forbidden):
                self.go(p, ep.method, ep.path, store)

    def test_the_kind_check_holds_on_its_own(self):
        # a malformed principal that looks like a user in every other field must still be refused
        store = bindings(*[RoleBinding(T1, "u-alice", r) for r in Role])
        for kind, extra in ((Kind.AGENT, {"agent_id": "agent-1"}), (Kind.SERVICE, {"service": "scanner"})):
            p = Principal(kind, "x", "client", tenant=T1, user_id="u-alice", **extra)
            for ep in ENDPOINTS:
                if not ep.public:
                    with self.assertRaises(Forbidden, msg=f"{kind} on {ep.method} {ep.path}"):
                        self.go(p, ep.method, ep.path, store)

    def test_service_principals_only_reach_their_internal_endpoints(self):
        d = directory()
        sc = d.resolve(claims("scanner-worker", "s", amr=()))
        gw = d.resolve(claims("gateway-service", "g", amr=()))
        allowed = {("scanner", ep.method, ep.path) for ep in INTERNAL_ENDPOINTS if ep.service == "scanner"} | \
                  {("gateway", ep.method, ep.path) for ep in INTERNAL_ENDPOINTS if ep.service == "gateway"}
        self.assertTrue(any(a[0] == "gateway" for a in allowed) and any(a[0] == "scanner" for a in allowed))
        for who, p in (("scanner", sc), ("gateway", gw)):
            for ep in INTERNAL_ENDPOINTS:
                if (who, ep.method, ep.path) in allowed:
                    self.go(p, ep.method, ep.path, RoleBindings())
                else:
                    with self.assertRaises(Forbidden):
                        self.go(p, ep.method, ep.path, RoleBindings())
            for ep in ENDPOINTS:
                if not ep.public:
                    with self.assertRaises(Forbidden):
                        self.go(p, ep.method, ep.path, RoleBindings())

    def test_users_cannot_call_internal_endpoints_whatever_their_roles(self):
        store = bindings(*[RoleBinding(T1, "u-alice", r) for r in Role])
        for ep in INTERNAL_ENDPOINTS:
            with self.assertRaises(Forbidden):
                self.go(user(), ep.method, ep.path, store)

    def test_scanner_cannot_reach_gateway_endpoint_and_vice_versa(self):
        d = directory()
        with self.assertRaises(Forbidden):
            self.go(d.resolve(claims("scanner-worker", "s", amr=())), "POST", "/internal/audit/events", RoleBindings())
        with self.assertRaises(Forbidden):
            self.go(d.resolve(claims("gateway-service", "g", amr=())), "POST", "/internal/scan-jobs/claim", RoleBindings())

    def test_forbidden_reason_is_stable_and_has_no_input(self):
        with self.assertRaises(Forbidden) as cm:
            self.go(user(), "GET", "/agents/SECRET-MARKER", RoleBindings())
        self.assertNotIn("SECRET-MARKER", str(cm.exception))


class SpecParity(unittest.TestCase):
    """The role table in code equals `docs/api-specification.md` Section 2 (drift fails the test)."""

    def parse(self):
        text = (ROOT / "docs/api-specification.md").read_text()
        section = text.split("## 2. Endpoint table", 1)[1].split("Not yet specified", 1)[0]
        rows = []
        for line in section.splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 3 or not cells[0].startswith(("GET", "POST", "PUT", "DELETE")):
                continue
            pairs = []
            for part in cells[0].split(";"):
                methods = re.findall(r"\b(GET|POST|PUT|DELETE|PATCH)\b", part.split("`", 1)[0])
                paths = re.findall(r"`([^`]+)`", part)
                pairs += list(itertools.product(methods, paths))
            roles = cells[2]
            rows.append((pairs, None if "unauthenticated" in roles else
                         {Role.from_code(c.strip()) for c in roles.split(",")}))
        return rows

    def test_endpoint_set_and_roles_match_the_specification(self):
        rows = self.parse()
        self.assertGreaterEqual(len(rows), 17)
        code = {(e.method, e.path): e for e in ENDPOINTS}
        doc_pairs = {p for pairs, _ in rows for p in pairs}
        self.assertEqual(set(code), doc_pairs)
        for pairs, roles in rows:
            if roles is None:
                self.assertTrue(all(code[p].public for p in pairs), pairs)
                continue
            union = set().union(*(code[p].roles for p in pairs))
            self.assertEqual(union, roles, pairs)

    def test_role_codes_cover_the_nine_roles(self):
        self.assertEqual(len(Role), 9)
        self.assertEqual({r.code for r in Role}, {"V", "AO", "SO", "SE", "AP", "SA", "AU", "IR", "PO"})


if __name__ == "__main__":
    unittest.main()
