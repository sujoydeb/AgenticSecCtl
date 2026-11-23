package agentic.authz_test

import rego.v1

import data.agentic.authz

hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

bundle := {"hash": hash, "generated_at": "2026-11-22T11:58:00Z", "max_age_seconds": 300}

reg := {"agent_server_allow": {"t1": {"a1": {"s1": true}}}}

grants := {"t1": {"a1": [
	{"tool": "s1__read_doc", "action_classes": ["read"], "resource_pattern": "docs/*"},
	{"tool": "s1__write_doc", "action_classes": ["write", "read"], "resource_pattern": "docs/*"},
	{"tool": "s1__purge", "action_classes": ["delete"]},
	{"tool": "s1__send", "action_classes": ["write"], "resource_pattern": "*"},
	{"tool": "s1__jit_read", "action_classes": ["read"], "grant_type": "jit"},
	{"tool": "s1__jit_ok", "action_classes": ["read"], "grant_type": "jit", "expires_at": "2026-11-22T12:30:00Z"},
	{"tool": "s1__bad_expiry", "action_classes": ["read"], "expires_at": "tomorrow"},
	{"tool": "s1__null_expiry", "action_classes": ["read"], "expires_at": null},
	{"tool": "s1__edge", "action_classes": ["read"], "expires_at": "2026-11-22T12:00:00Z"},
]}}

tool(id, ac) := {"id": id, "status": "approved", "action_class": ac, "classification": "Internal", "hash_ok": true}

base := {
	"tenant": "t1",
	"agent": {"id": "a1", "status": "active", "env": "prod"},
	"server": {"id": "s1", "status": "approved", "classification": "Internal"},
	"tool": tool("s1__read_doc", "read"),
	"resource": "docs/handbook",
	"args_digest": "sha256:abc",
	"session": {"taint": "clean", "max_classification": "Internal", "call_count": 1},
	"approval": {"valid": false},
	"now": "2026-11-22T12:00:00Z",
}

decide(i) := d if {
	d := authz.decision with input as i with data.registry as reg with data.grants as grants with data.bundle as bundle
}

decide_with(i, r, g, b) := d if {
	d := authz.decision with input as i with data.registry as r with data.grants as g with data.bundle as b
}

with_tool(t) := object.union(base, {"tool": t})

# name, input, expected allow, reasons that must be present (all others are allowed to appear too)
cases := [
	{"name": "allow read with grant", "input": base, "allow": true, "reasons": []},
	# AC-3, TC-F1: unregistered, revoked, suspended agents; unapproved server or tool
	{"name": "unregistered agent", "input": object.union(base, {"agent": {"id": "ghost", "status": "active"}}), "allow": false, "reasons": ["agent_server_not_allowed", "no_grant"]},
	{"name": "revoked agent", "input": object.union(base, {"agent": {"id": "a1", "status": "revoked"}}), "allow": false, "reasons": ["agent_inactive"]},
	{"name": "suspended agent", "input": object.union(base, {"agent": {"id": "a1", "status": "suspended"}}), "allow": false, "reasons": ["agent_inactive"]},
	{"name": "pending agent", "input": object.union(base, {"agent": {"id": "a1", "status": "pending"}}), "allow": false, "reasons": ["agent_inactive"]},
	{"name": "quarantined server", "input": object.union(base, {"server": {"id": "s1", "status": "quarantined"}}), "allow": false, "reasons": ["server_not_approved"]},
	{"name": "pending tool", "input": with_tool({"id": "s1__read_doc", "status": "pending", "action_class": "read", "hash_ok": true}), "allow": false, "reasons": ["tool_not_approved"]},
	{"name": "quarantined tool", "input": with_tool({"id": "s1__read_doc", "status": "quarantined", "action_class": "read", "hash_ok": true}), "allow": false, "reasons": ["tool_not_approved"]},
	# TC-B1: pin mismatch beats every grant
	{"name": "hash mismatch", "input": with_tool({"id": "s1__read_doc", "status": "approved", "action_class": "read", "hash_ok": false}), "allow": false, "reasons": ["tool_hash_mismatch"]},
	# TC-E1: read-only grant cannot write or delete
	{"name": "read grant cannot write", "input": with_tool(tool("s1__read_doc", "write")), "allow": false, "reasons": ["no_grant"]},
	{"name": "read grant cannot execute", "input": with_tool(tool("s1__read_doc", "execute")), "allow": false, "reasons": ["no_grant"]},
	{"name": "read grant cannot delete", "input": with_tool(tool("s1__read_doc", "delete")), "allow": false, "reasons": ["no_grant"]},
	{"name": "no grant for tool", "input": with_tool(tool("s1__unknown", "read")), "allow": false, "reasons": ["no_grant"]},
	# TC-C3: unlisted pair
	{"name": "other server not allowed", "input": object.union(base, {"server": {"id": "s2", "status": "approved"}}), "allow": false, "reasons": ["agent_server_not_allowed"]},
	{"name": "other tenant", "input": object.union(base, {"tenant": "t2"}), "allow": false, "reasons": ["agent_server_not_allowed", "no_grant"]},
	# resource patterns (FR-AUTHZ-3)
	{"name": "resource outside pattern", "input": object.union(base, {"resource": "finance/q3"}), "allow": false, "reasons": ["no_grant"]},
	{"name": "resource prefix is not substring", "input": object.union(base, {"resource": "xdocs/handbook"}), "allow": false, "reasons": ["no_grant"]},
	{"name": "resource traversal refused", "input": object.union(base, {"resource": "docs/../finance/q3"}), "allow": false, "reasons": ["input_invalid"]},
	{"name": "resource traversal backslash refused", "input": object.union(base, {"resource": "docs\\..\\finance"}), "allow": false, "reasons": ["input_invalid"]},
	{"name": "resource leading traversal refused", "input": object.union(base, {"resource": "../etc/passwd"}), "allow": false, "reasons": ["input_invalid"]},
	{"name": "dots inside a name are fine", "input": object.union(base, {"resource": "docs/a..b"}), "allow": true, "reasons": []},
	{"name": "unrestricted pattern matches anything", "input": object.union(base, {"tool": tool("s1__purge", "delete"), "resource": "anything", "approval": {"valid": true}}), "allow": true, "reasons": []},
	# TC-E3: expiry
	{"name": "jit grant before expiry", "input": with_tool(tool("s1__jit_ok", "read")), "allow": true, "reasons": []},
	{"name": "jit grant after expiry", "input": object.union(with_tool(tool("s1__jit_ok", "read")), {"now": "2026-11-22T12:30:00Z"}), "allow": false, "reasons": ["no_grant"]},
	{"name": "jit grant without expiry", "input": with_tool(tool("s1__jit_read", "read")), "allow": false, "reasons": ["no_grant"]},
	{"name": "unparsable expiry is not live", "input": with_tool(tool("s1__bad_expiry", "read")), "allow": false, "reasons": ["no_grant"]},
	{"name": "null expiry on a static grant is live", "input": with_tool(tool("s1__null_expiry", "read")), "allow": true, "reasons": []},
	{"name": "boundary second is expired", "input": with_tool(tool("s1__edge", "read")), "allow": false, "reasons": ["no_grant"]},
	{"name": "one second before the boundary", "input": object.union(with_tool(tool("s1__edge", "read")), {"now": "2026-11-22T11:59:59Z"}), "allow": true, "reasons": []},
	# TC-D4: approval for high impact
	{"name": "delete needs approval", "input": object.union(with_tool(tool("s1__purge", "delete")), {"resource": "x"}), "allow": false, "reasons": ["approval_required"]},
	{"name": "delete with approval", "input": object.union(with_tool(tool("s1__purge", "delete")), {"resource": "x", "approval": {"valid": true}}), "allow": true, "reasons": []},
	{"name": "write to confidential needs approval", "input": with_tool({"id": "s1__write_doc", "status": "approved", "action_class": "write", "classification": "Confidential", "hash_ok": true}), "allow": false, "reasons": ["approval_required"]},
	{"name": "write with unknown classification needs approval", "input": json.remove(with_tool(tool("s1__write_doc", "write")), ["/tool/classification"]), "allow": false, "reasons": ["approval_required"]},
	{"name": "write to internal is not high impact", "input": with_tool(tool("s1__write_doc", "write")), "allow": true, "reasons": []},
	# TC-D5: taint
	{"name": "tainted write", "input": object.union(with_tool(tool("s1__send", "write")), {"session": {"taint": "untrusted_read_of_sensitive"}}), "allow": false, "reasons": ["taint_block"]},
	{"name": "tainted read is fine", "input": object.union(base, {"session": {"taint": "untrusted_read_of_sensitive"}}), "allow": true, "reasons": []},
	{"name": "tainted write with approval", "input": object.union(with_tool(tool("s1__send", "write")), {"session": {"taint": "untrusted_read_of_sensitive"}, "approval": {"valid": true}}), "allow": true, "reasons": []},
	# AC-7, TC-Z5: bundle handling is covered below; here the empty and hostile inputs
	{"name": "empty input", "input": {}, "allow": false, "reasons": ["input_invalid"]},
	{"name": "input is not an object", "input": "allow", "allow": false, "reasons": ["input_invalid"]},
]

# One case per required field removed, and per wrong type (fail closed on every input field)
required_paths := [
	["tenant"], ["agent", "id"], ["agent", "status"], ["server", "id"], ["server", "status"],
	["tool", "id"], ["tool", "status"], ["tool", "action_class"], ["tool", "hash_ok"],
	["resource"], ["args_digest"], ["approval"], ["approval", "valid"], ["now"],
]

bad_values := [
	{"path": ["tenant"], "value": 5}, {"path": ["tenant"], "value": ""}, {"path": ["agent", "id"], "value": ""},
	{"path": ["tool", "action_class"], "value": "admin"}, {"path": ["tool", "action_class"], "value": ["read"]},
	{"path": ["tool", "hash_ok"], "value": "true"}, {"path": ["tool", "hash_ok"], "value": 1},
	{"path": ["approval", "valid"], "value": "yes"}, {"path": ["approval", "valid"], "value": 1},
	{"path": ["now"], "value": "garbage"}, {"path": ["now"], "value": 1700000000}, {"path": ["now"], "value": "2026-11-22"},
	{"path": ["resource"], "value": null}, {"path": ["args_digest"], "value": ""}, {"path": ["args_digest"], "value": null},
]

case_failures contains c.name if {
	some c in cases
	not case_ok(c)
}

case_ok(c) if {
	d := decide(c.input)
	d.allow == c.allow
	every r in c.reasons {
		r in d.reasons
	}
	invariant_ok(d)
	d.policy_hash == hash
}

# allowed iff no reasons; every decision carries the bundle hash
invariant_ok(d) if {
	d.allow
	count(d.reasons) == 0
}

invariant_ok(d) if {
	not d.allow
	count(d.reasons) > 0
}

test_decision_table if {
	print("failing cases:", case_failures)
	count(case_failures) == 0
}

test_every_required_field_missing_denies if {
	bad := [p |
		some p in required_paths
		d := decide(json.remove(base, [concat("/", p)]))
		not denied_with(d, "input_invalid")
	]
	print("not denied:", bad)
	count(bad) == 0
}

test_wrong_types_deny if {
	bad := [b |
		some b in bad_values
		d := decide(json.patch(base, [{"op": "replace", "path": concat("/", array.concat([""], b.path)), "value": b.value}]))
		not denied_with(d, "input_invalid")
	]
	print("not denied:", bad)
	count(bad) == 0
}

denied_with(d, reason) if {
	d.allow == false
	reason in d.reasons
}

# ---------------------------------------------------------------- bundle (FR-POL-2, FR-AUTHZ-8, CTL-16, TC-Z5)

test_decision_carries_bundle_hash if {
	d := decide(base)
	d.policy_hash == hash
	d.allow
}

test_denial_carries_bundle_hash if {
	d := decide(object.union(base, {"agent": {"id": "ghost", "status": "active"}}))
	d.policy_hash == hash
	not d.allow
}

test_no_bundle_denies if {
	i := base
	d := authz.decision with input as i with data.registry as reg with data.grants as grants
	not d.allow
	"bundle_missing" in d.reasons
	d.policy_hash == ""
}

test_stale_bundle_denies_at_the_limit if {
	# generated 11:58:00, limit 300 s: fresh at 12:02:59, stale from 12:03:00
	fresh := decide(object.union(base, {"now": "2026-11-22T12:02:59Z"}))
	fresh.allow
	at := decide(object.union(base, {"now": "2026-11-22T12:03:00Z"}))
	not at.allow
	"bundle_stale" in at.reasons
	late := decide(object.union(base, {"now": "2026-11-23T12:00:00Z"}))
	"bundle_stale" in late.reasons
}

test_future_dated_bundle_denies if {
	b := object.union(bundle, {"generated_at": "2026-11-22T12:05:00Z"})
	d := decide_with(base, reg, grants, b)
	not d.allow
	"bundle_invalid" in d.reasons

	# within the 60 s skew tolerance it still counts as fresh
	b2 := object.union(bundle, {"generated_at": "2026-11-22T12:00:30Z"})
	decide_with(base, reg, grants, b2).allow
}

test_malformed_bundles_deny if {
	bad := [b |
		some b in [
			{}, {"hash": hash}, "bundle", [],
			object.union(bundle, {"hash": "short"}), object.union(bundle, {"hash": 5}),
			object.union(bundle, {"hash": "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}),
			object.union(bundle, {"max_age_seconds": 0}), object.union(bundle, {"max_age_seconds": -5}),
			object.union(bundle, {"max_age_seconds": "300"}), object.union(bundle, {"generated_at": "yesterday"}),
			object.union(bundle, {"generated_at": 5}),
		]
		d := decide_with(base, reg, grants, b)
		d.allow
	]
	print("allowed with a bad bundle:", bad)
	count(bad) == 0
}

test_bad_bundle_reports_no_hash_of_unknown_type if {
	d := decide_with(base, reg, grants, object.union(bundle, {"hash": 5}))
	d.policy_hash == ""
}

# ---------------------------------------------------------------- data absent

test_missing_registry_and_grants_deny if {
	d := authz.decision with input as base with data.bundle as bundle
	not d.allow
	"agent_server_not_allowed" in d.reasons
	"no_grant" in d.reasons
}

test_registry_value_must_be_true if {
	r := {"agent_server_allow": {"t1": {"a1": {"s1": "yes"}}}}
	not decide_with(base, r, grants, bundle).allow
	r2 := {"agent_server_allow": {"t1": {"a1": {"s1": false}}}}
	not decide_with(base, r2, grants, bundle).allow
}

test_unknown_tenant_has_no_data if {
	d := decide(object.union(base, {"tenant": "nope"}))
	not d.allow
}

test_obligations_listed if {
	d := decide(object.union(with_tool(tool("s1__purge", "delete")), {"resource": "x"}))
	d.obligations == ["require_approval"]
	decide(base).obligations == []
}

# The decision is the only output a gateway reads: it is always an object with the four fields.
test_decision_shape_for_hostile_inputs if {
	every i in [{}, "x", [], null, 5, {"tenant": "t1"}, {"agent": 5}] {
		d := decide(i)
		is_boolean(d.allow)
		is_array(d.reasons)
		is_array(d.obligations)
		is_string(d.policy_hash)
		d.allow == false
	}
}
