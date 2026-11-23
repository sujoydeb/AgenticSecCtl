"""Decision replay (FR-AUD-6, TC-Z20): re-evaluate a stored decision from the
policy bundle hash and the input it was made on. A record that cannot be
replayed (missing bundle, digest mismatch, evaluator error) counts as a
mismatch, never as a skip."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .canonical import canonicalize, sha256_hex


class ReplayError(Exception):
    pass


def input_digest(policy_input: Any) -> str:
    return sha256_hex(canonicalize(policy_input))


@dataclass
class ReplayReport:
    checked: int = 0
    mismatches: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.mismatches


def replay_decisions(records: Iterable[dict[str, Any]],
                     bundles: dict[str, Callable[[dict], dict]]) -> ReplayReport:
    rep = ReplayReport()
    for rec in records:
        rep.checked += 1
        def bad(reason: str) -> None:
            rep.mismatches.append({"record": rec.get("input_digest"), "reason": reason})
        evaluator = bundles.get(rec.get("policy_hash"))
        if evaluator is None:
            bad("policy bundle not available for the stored hash"); continue
        try:
            if input_digest(rec["input"]) != rec["input_digest"]:
                bad("input digest does not match the stored input"); continue
            got = "allow" if evaluator(rec["input"]).get("allow") is True else "deny"
        except Exception as exc:  # fail closed: an unreplayable record is a failure
            bad(f"replay failed: {type(exc).__name__}"); continue
        if got != rec.get("decision"):
            bad(f"replayed {got}, stored {rec.get('decision')}")
    return rep
