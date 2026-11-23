"""Shared contracts: the audit event vocabulary (single definition is
``Plan/architecture.md`` Section 4.8; a test keeps this copy equal to it)."""
from __future__ import annotations

EVENT_TYPES: frozenset[str] = frozenset("""
register.denied server.registered import.failed scan.completed finding.created tool.approved tool.rejected
tool.quarantined override.requested override.approved authn.fail authz.allow authz.deny
approval.requested approval.granted approval.denied ssrf.blocked dlp.match inject.signal
limit.exceeded session.suspended delegation.denied grant.created grant.expired policy.changed
incident.opened audit.verify.failed egress.blocked discovery.asset anchor.created
audit.buffer_full breakglass.used card.rejected classification.changed client.registered
client.denied config.changed content.blocked legalhold.set notification.failed
retention.executed scan.timeout key.rotated evidence.accessed emergency.declared
""".split())
