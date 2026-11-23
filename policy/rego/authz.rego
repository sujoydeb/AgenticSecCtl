package agentic.authz

import rego.v1

# Product policy for Phase 1 (WP-1.8). Contract: docs/authn-authz-design.md Sections 4 and 5.
#
# Query data.agentic.authz.decision. It always returns {allow, reasons, obligations, policy_hash}:
#   - allow is true only when every positive condition holds (default deny);
#   - reasons are stable codes, empty when allowed and never empty when denied (tested);
#   - obligations carry require_approval and the like;
#   - policy_hash is the hash of the bundle that produced the decision (FR-POL-2), "" if unknown.
#
# Fail closed: a missing or mistyped input field, a missing, malformed or stale bundle, an unparsable
# grant expiry, all deny. Data shape:
#   data.bundle   = {hash, generated_at, max_age_seconds}      (written by policy/build_bundle.py and the publisher)
#   data.registry.agent_server_allow[tenant][agent][server] = true
#   data.grants[tenant][agent] = [{tool, action_classes, resource_pattern?, expires_at?, grant_type?}, ...]

default allow := false

allow if {
	input_valid
	bundle_fresh
	input.agent.status == "active"
	input.server.status == "approved"
	input.tool.status == "approved"
	input.tool.hash_ok == true
	agent_server_allowed
	permitted
	not approval_needed
	not tainted_send_blocked
}

decision := {
	"allow": allow,
	"reasons": sort([r | some r in reasons]),
	"obligations": sort([o | some o in obligations]),
	"policy_hash": policy_hash,
}

policy_hash := data.bundle.hash if is_string(data.bundle.hash)

default policy_hash := ""

# ---------------------------------------------------------------- input validation

action_classes := {"read", "write", "execute", "delete"}

input_valid if {
	non_empty_string(input.tenant)
	non_empty_string(input.agent.id)
	is_string(input.agent.status)
	non_empty_string(input.server.id)
	is_string(input.server.status)
	non_empty_string(input.tool.id)
	is_string(input.tool.status)
	input.tool.action_class in action_classes
	is_boolean(input.tool.hash_ok)
	is_string(input.resource)
	not path_traversal(input.resource)
	non_empty_string(input.args_digest)
	is_boolean(input.approval.valid)
	valid_time(input.now)
}

non_empty_string(x) if {
	is_string(x)
	x != ""
}

valid_time(t) if {
	is_string(t)
	is_number(time.parse_rfc3339_ns(t))
}

# A resource containing a parent-directory segment is refused outright: a prefix pattern such as
# "docs/*" would otherwise accept "docs/../finance/q3".
path_traversal(resource) if {
	some seg in split(replace(resource, "\\", "/"), "/")
	seg == ".."
}

# ---------------------------------------------------------------- bundle freshness (FR-AUTHZ-8, CTL-16)

bundle_present if is_object(data.bundle)

bundle_valid if {
	bundle_present
	is_string(data.bundle.hash)
	regex.match(`^[0-9a-f]{64}$`, data.bundle.hash)
	is_number(data.bundle.max_age_seconds)
	data.bundle.max_age_seconds > 0
	is_number(time.parse_rfc3339_ns(data.bundle.generated_at))
}

# Age in seconds. A bundle dated more than 60 s in the future is invalid (clock fault), not fresh.
bundle_age_seconds := (time.parse_rfc3339_ns(input.now) - time.parse_rfc3339_ns(data.bundle.generated_at)) / 1e9 if {
	bundle_valid
	valid_time(input.now)
}

bundle_fresh if {
	bundle_age_seconds >= -60
	bundle_age_seconds < data.bundle.max_age_seconds
}

# ---------------------------------------------------------------- registry and grants

agent_server_allowed if data.registry.agent_server_allow[input.tenant][input.agent.id][input.server.id] == true

permitted if {
	some grant in data.grants[input.tenant][input.agent.id]
	grant.tool == input.tool.id
	input.tool.action_class in grant.action_classes
	resource_matches(object.get(grant, "resource_pattern", "*"), input.resource)
	grant_live(grant)
}

# A static grant without expiry is live; any expiry must parse and lie strictly in the future (the boundary
# second is expired). A just-in-time grant without expiry, or an unparsable expiry, is never live.
grant_live(grant) if {
	object.get(grant, "expires_at", null) == null
	object.get(grant, "grant_type", "static") == "static"
}

grant_live(grant) if {
	time.parse_rfc3339_ns(grant.expires_at) > time.parse_rfc3339_ns(input.now)
}

# "*" matches anything; a trailing "*" matches a prefix; otherwise exact.
resource_matches(pattern, _) if pattern == "*"

resource_matches(pattern, resource) if {
	pattern != "*"
	endswith(pattern, "*")
	startswith(resource, trim_suffix(pattern, "*"))
}

resource_matches(pattern, resource) if {
	not endswith(pattern, "*")
	pattern == resource
}

# ---------------------------------------------------------------- impact and taint

high_impact if input.tool.action_class == "delete"

# Write and execute are high impact unless the tool is known to be Public or Internal; an unknown
# classification counts as sensitive.
high_impact if {
	input.tool.action_class in {"write", "execute"}
	not low_classification
}

low_classification if input.tool.classification in {"Public", "Internal"}

approval_needed if {
	high_impact
	input.approval.valid != true
}

tainted_send_blocked if {
	input.session.taint == "untrusted_read_of_sensitive"
	input.tool.action_class in {"write", "execute"}
	input.approval.valid != true
}

# ---------------------------------------------------------------- obligations and reasons

obligations contains "require_approval" if {
	input_valid
	approval_needed
}

reasons contains "input_invalid" if not input_valid

reasons contains "bundle_missing" if not bundle_present

reasons contains "bundle_invalid" if {
	bundle_present
	not bundle_valid
}

reasons contains "bundle_invalid" if {
	bundle_valid
	valid_time(input.now)
	bundle_age_seconds < -60
}

reasons contains "bundle_stale" if {
	bundle_valid
	valid_time(input.now)
	bundle_age_seconds >= data.bundle.max_age_seconds
}

# Facts about the request are only reported when the input is well formed.
reasons contains "agent_inactive" if {
	input_valid
	input.agent.status != "active"
}

reasons contains "server_not_approved" if {
	input_valid
	input.server.status != "approved"
}

reasons contains "tool_not_approved" if {
	input_valid
	input.tool.status != "approved"
}

reasons contains "tool_hash_mismatch" if {
	input_valid
	input.tool.hash_ok != true
}

reasons contains "agent_server_not_allowed" if {
	input_valid
	not agent_server_allowed
}

reasons contains "no_grant" if {
	input_valid
	not permitted
}

reasons contains "approval_required" if {
	input_valid
	approval_needed
}

reasons contains "taint_block" if {
	input_valid
	tainted_send_blocked
}
