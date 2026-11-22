package agentic.authz_test

import rego.v1

import data.agentic.authz

base := {
	"tenant": "t1",
	"agent": {"id": "a1", "status": "active", "env": "prod"},
	"server": {"id": "s1", "status": "approved", "classification": "Internal"},
	"tool": {"id": "s1__read_doc", "status": "approved", "action_class": "read", "classification": "Internal", "hash_ok": true},
	"resource": "docs/handbook",
	"args_digest": "sha256:abc",
	"session": {"taint": "clean", "max_classification": "Internal", "call_count": 1},
	"approval": {"valid": false},
	"now": "2026-11-22T12:00:00Z",
}

reg := {"agent_server_allow": {"t1": {"a1": {"s1": true}}}}

grants := {"t1": {"a1": [{"tool": "s1__read_doc", "action_classes": ["read"], "resource_pattern": "docs/*"}]}}

test_allow_read_with_grant if {
	authz.allow with input as base with data.registry as reg with data.grants as grants
}

# TC-F1: unregistered and revoked agents
test_unregistered_agent_denied if {
	not authz.allow with input as object.union(base, {"agent": {"id": "ghost", "status": "active", "env": "prod"}}) with data.registry as reg with data.grants as grants
}

test_revoked_agent_denied if {
	not authz.allow with input as object.union(base, {"agent": {"id": "a1", "status": "revoked", "env": "prod"}}) with data.registry as reg with data.grants as grants
}

# TC-E1: read-only grant cannot write or delete
test_read_grant_cannot_write if {
	i := object.union(base, {"tool": {"id": "s1__read_doc", "status": "approved", "action_class": "write", "classification": "Internal", "hash_ok": true}})
	not authz.allow with input as i with data.registry as reg with data.grants as grants
	"no_grant" in authz.reasons with input as i with data.registry as reg with data.grants as grants
}

test_read_grant_cannot_delete if {
	i := object.union(base, {"tool": {"id": "s1__read_doc", "status": "approved", "action_class": "delete", "classification": "Internal", "hash_ok": true}})
	not authz.allow with input as i with data.registry as reg with data.grants as grants
}

# TC-C3: unlisted agent-to-server pair
test_unlisted_pair_denied if {
	not authz.allow with input as base with data.registry as {"agent_server_allow": {"t1": {}}} with data.grants as grants
}

# TC-B1: hash mismatch denied whatever the grants
test_hash_mismatch_denied if {
	i := object.union(base, {"tool": {"id": "s1__read_doc", "status": "approved", "action_class": "read", "classification": "Internal", "hash_ok": false}})
	not authz.allow with input as i with data.registry as reg with data.grants as grants
	"tool_hash_mismatch" in authz.reasons with input as i with data.registry as reg with data.grants as grants
}

# TC-E3: a grant is valid before its expiry and expired from the boundary second on
test_grant_expiry_boundary if {
	g := {"t1": {"a1": [{"tool": "s1__read_doc", "action_classes": ["read"], "resource_pattern": "docs/*", "expires_at": "2026-11-22T12:00:00Z"}]}}
	early := object.union(base, {"now": "2026-11-22T11:59:59Z"})
	authz.allow with input as early with data.registry as reg with data.grants as g
	at := object.union(base, {"now": "2026-11-22T12:00:00Z"})
	not authz.allow with input as at with data.registry as reg with data.grants as g
	late := object.union(base, {"now": "2026-11-22T12:00:01Z"})
	not authz.allow with input as late with data.registry as reg with data.grants as g
}

# Regression for the sketch: a not-yet-expired grant must not be treated as expired
test_future_expiry_not_expired if {
	g := {"t1": {"a1": [{"tool": "s1__read_doc", "action_classes": ["read"], "resource_pattern": "docs/*", "expires_at": "2027-01-01T00:00:00Z"}]}}
	authz.allow with input as base with data.registry as reg with data.grants as g
}

# TC-D4 / TC-K3: high-impact call without bound approval requires approval
test_high_impact_requires_approval if {
	g := {"t1": {"a1": [{"tool": "s1__purge", "action_classes": ["delete"], "resource_pattern": "*"}]}}
	i := object.union(base, {"tool": {"id": "s1__purge", "status": "approved", "action_class": "delete", "classification": "Internal", "hash_ok": true}})
	not authz.allow with input as i with data.registry as reg with data.grants as g
	"require_approval" in authz.obligations with input as i with data.registry as reg with data.grants as g
	ok := object.union(i, {"approval": {"valid": true}})
	authz.allow with input as ok with data.registry as reg with data.grants as g
}

# TC-D5: tainted session write denied
test_tainted_write_denied if {
	g := {"t1": {"a1": [{"tool": "s1__send", "action_classes": ["write"], "resource_pattern": "*"}]}}
	i := object.union(base, {
		"tool": {"id": "s1__send", "status": "approved", "action_class": "write", "classification": "Internal", "hash_ok": true},
		"session": {"taint": "untrusted_read_of_sensitive", "max_classification": "Confidential", "call_count": 3},
	})
	not authz.allow with input as i with data.registry as reg with data.grants as g
	"taint_block" in authz.reasons with input as i with data.registry as reg with data.grants as g
}

# Fail closed: a missing input field must deny, not pass
test_missing_tool_status_denies if {
	i := {"tenant": "t1", "agent": base.agent, "server": base.server, "tool": {"id": "s1__read_doc", "action_class": "read", "hash_ok": true}, "resource": "docs/x", "approval": {"valid": false}, "now": base.now}
	not authz.allow with input as i with data.registry as reg with data.grants as grants
}

test_empty_input_denies if {
	not authz.allow with input as {} with data.registry as reg with data.grants as grants
}

test_unknown_tenant_denies if {
	not authz.allow with input as object.union(base, {"tenant": "other"}) with data.registry as reg with data.grants as grants
}

# resource patterns
test_resource_outside_pattern_denied if {
	not authz.allow with input as object.union(base, {"resource": "finance/q3"}) with data.registry as reg with data.grants as grants
}
