"""Domain errors of the management API. Each maps to a code in the error catalogue (common.errors);
none carries input text. ``audit`` says which event the HTTP layer records for the refusal."""
from __future__ import annotations


class DomainError(Exception):
    code = "internal"
    audit: str | None = None

    def __init__(self, detail: str = ""):
        super().__init__(self.code)
        self.detail = detail  # for the audit excerpt and logs only, never shown to the caller


class Invalid(DomainError):
    code = "invalid-request"


class NotFound(DomainError):
    code = "not-found"


class Conflict(DomainError):
    code = "conflict"


class SeparationOfDuties(DomainError):
    code = "separation-of-duties"
    audit = "authz.deny"


class SsrfRefused(DomainError):
    code = "ssrf-rejected"
    audit = "register.denied"
