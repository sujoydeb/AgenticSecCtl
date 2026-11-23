"""WP-1.10: the development realm has a user per role, MFA, and no shared or static secrets."""
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
REALM = json.loads((ROOT / "deploy/compose/keycloak/realm-dev.json").read_text())
ROLES = {"viewer", "agent-owner", "server-owner", "security-engineer", "approver", "approver-2",
         "security-admin", "auditor", "incident-responder", "platform-operator"}


def walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            yield k, v
            yield from walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from walk(v)


class Realm(unittest.TestCase):
    def clients(self):
        return {c["clientId"]: c for c in REALM["clients"]}

    def test_user_for_every_role_with_totp_required(self):
        users = {u["username"]: u for u in REALM["users"]}
        self.assertEqual(set(users), ROLES)
        for u in users.values():
            self.assertIn("CONFIGURE_TOTP", u["requiredActions"], u["username"])
            self.assertEqual(len(u["attributes"]["tenant_id"]), 1)

    def test_no_secrets_or_passwords_in_the_file(self):
        keys = {k.lower() for k, _ in walk(REALM)}
        self.assertFalse({"secret", "credentials", "password", "value"} & keys)

    def test_no_password_grant_or_implicit_flow_anywhere(self):
        for c in REALM["clients"]:
            self.assertFalse(c["directAccessGrantsEnabled"], c["clientId"])
            self.assertFalse(c["implicitFlowEnabled"], c["clientId"])

    def test_dashboard_is_public_pkce_s256(self):
        d = self.clients()["dashboard"]
        self.assertTrue(d["publicClient"] and d["standardFlowEnabled"])
        self.assertEqual(d["attributes"]["pkce.code.challenge.method"], "S256")
        self.assertTrue(all(u.startswith("http://127.0.0.1") for u in d["redirectUris"]))
        names = {m["name"] for m in d["protocolMappers"]}
        self.assertTrue({"tenant_id", "amr", "gateway-audience"} <= names)

    def test_machine_clients_are_distinct_and_use_signed_jwt_authentication(self):
        machine = [c for c in REALM["clients"] if c["clientId"] != "dashboard"]
        ids = [c["clientId"] for c in machine]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual({"scanner-worker", "gateway-service"} - set(ids), set())
        self.assertGreaterEqual(len([i for i in ids if i.startswith("agent-client-")]), 3)
        for c in machine:
            self.assertEqual(c["clientAuthenticatorType"], "client-jwt", c["clientId"])
            self.assertTrue(c["serviceAccountsEnabled"] and not c["standardFlowEnabled"])
            self.assertFalse(c["publicClient"])

    def test_agent_tokens_carry_the_gateway_audience(self):
        for cid, c in self.clients().items():
            if cid.startswith("agent-client-"):
                self.assertIn("gateway-audience", {m["name"] for m in c["protocolMappers"]})

    def test_token_lifetime_within_limit(self):
        self.assertLessEqual(REALM["accessTokenLifespan"], 600)
        for c in REALM["clients"]:
            self.assertLessEqual(int(c["attributes"]["access.token.lifespan"]), 600)
        self.assertEqual(REALM["defaultSignatureAlgorithm"], "RS256")

    def test_compose_imports_the_realm(self):
        text = (ROOT / "deploy/compose/compose.dev.yml").read_text()
        self.assertIn("--import-realm", text)
        self.assertIn("realm-dev.json", text)


if __name__ == "__main__":
    unittest.main()
