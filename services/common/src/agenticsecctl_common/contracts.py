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

# Risk score weights per severity (specification Section 4.6): score = min(100, sum(weight * confidence)).
SEVERITY_WEIGHTS: dict[str, int] = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def risk_score(pairs: "list[tuple[str, float]]") -> float:
    """Reproducible risk score from (severity, confidence) pairs."""
    return round(min(100.0, sum(SEVERITY_WEIGHTS[sev] * conf for sev, conf in pairs)), 2)
