package agentic.authz

import rego.v1

# Spike S3 draft, from docs/authn-authz-design.md Section 6. Not the product policy.

default allow := false

allow if {
	input.agent.status == "active"
	input.server.status == "approved"
	input.tool.status == "approved"
	input.tool.hash_ok
	agent_server_allowed
	permitted
	not high_impact_without_approval
	not tainted_send_blocked
}

# Data shape: allow[tenant][agent][server] = true. Keyed lookup, not a list scan (measured about 20 times faster).
agent_server_allowed if data.registry.agent_server_allow[input.tenant][input.agent.id][input.server.id]

permitted if {
	some grant in data.grants[input.tenant][input.agent.id]
	grant.tool == input.tool.id
	input.tool.action_class in grant.action_classes
	resource_matches(grant.resource_pattern, input.resource)
	not expired(grant)
}

# A grant is valid strictly before its expiry: at the boundary second it is expired (fail closed).
# Both sides are parsed; comparing the parsed integer with the raw input.now string is always true in Rego.
expired(grant) if {
	grant.expires_at
	time.parse_rfc3339_ns(grant.expires_at) <= time.parse_rfc3339_ns(input.now)
}

# Pattern "*" matches anything; a trailing "*" matches a prefix; otherwise exact.
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

high_impact if input.tool.action_class == "delete"

high_impact if {
	input.tool.classification in {"Confidential", "Restricted"}
	input.tool.action_class in {"write", "execute"}
}

high_impact_without_approval if {
	high_impact
	not input.approval.valid
}

tainted_send_blocked if {
	input.session.taint == "untrusted_read_of_sensitive"
	input.tool.action_class in {"write", "execute"}
	not input.approval.valid
}

obligations contains "require_approval" if {
	high_impact
	not input.approval.valid
}

reasons contains "no_grant" if not permitted

reasons contains "tool_hash_mismatch" if not input.tool.hash_ok

reasons contains "taint_block" if tainted_send_blocked
