"""Roles, role bindings and the endpoint role table (spec Section 2, API spec Section 2, CTL-23).

Default deny: an endpoint that is not in the table, a principal without a live
binding, an agent or a service on a management endpoint, a person on an
internal endpoint, all raise ``Forbidden``. The table is checked against
``docs/api-specification.md`` by a test, so the two cannot drift apart.
Separation-of-duties checks that compare actor and requester live with the
objects (WP-1.6) and in the database constraints.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime

from .principals import Kind, Principal


class Forbidden(Exception):
    """Stable code only; never echoes the path, the user or any input."""

    def __init__(self, reason: str = "forbidden"):
        super().__init__(reason)
        self.reason = reason


class Role(enum.Enum):
    VIEWER = ("viewer", "V")
    AGENT_OWNER = ("agent_owner", "AO")
    SERVER_OWNER = ("server_owner", "SO")
    SECURITY_ENGINEER = ("security_engineer", "SE")
    APPROVER = ("approver", "AP")
    SECURITY_ADMIN = ("security_admin", "SA")
    AUDITOR = ("auditor", "AU")
    INCIDENT_RESPONDER = ("incident_responder", "IR")
    PLATFORM_OPERATOR = ("platform_operator", "PO")

    @property
    def db_name(self) -> str:
        return self.value[0]

    @property
    def code(self) -> str:
        return self.value[1]

    @classmethod
    def from_code(cls, code: str) -> Role:
        for r in cls:
            if r.code == code:
                return r
        raise KeyError(code)


V, AO, SO, SE, AP, SA, AU, IR, PO = (Role.VIEWER, Role.AGENT_OWNER, Role.SERVER_OWNER, Role.SECURITY_ENGINEER,
                                     Role.APPROVER, Role.SECURITY_ADMIN, Role.AUDITOR, Role.INCIDENT_RESPONDER,
                                     Role.PLATFORM_OPERATOR)


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    roles: frozenset[Role]
    public: bool = False


@dataclass(frozen=True)
class InternalEndpoint:
    method: str
    path: str
    service: str


def _e(method: str, path: str, *roles: Role) -> Endpoint:
    return Endpoint(method, path, frozenset(roles))


ENDPOINTS: tuple[Endpoint, ...] = (
    _e("GET", "/agents", V, AO, SE, AP, AU), _e("GET", "/agents/{id}", V, AO, SE, AP, AU),
    _e("POST", "/agents", AO),
    _e("PUT", "/agents/{id}/suspension", SE, IR), _e("DELETE", "/agents/{id}/suspension", SE, AP, IR),
    _e("GET", "/servers", V, SO, SE), _e("POST", "/servers", SO, SE),
    _e("POST", "/servers/{id}/imports", SO, SE), _e("POST", "/servers/{id}/definitions", SO, SE),
    _e("GET", "/tools/{id}", V, SO, SE, AP, AU), _e("GET", "/tools/{id}/versions", V, SO, SE, AP, AU),
    _e("GET", "/tools/{id}/diff", V, SO, SE, AP, AU),
    _e("PUT", "/tools/{id}/quarantine", SE, IR),
    _e("GET", "/approvals", AP, SE), _e("POST", "/approvals/{id}/decision", AP, SE),
    _e("POST", "/approvals/{id}/overrides", SE, AP), _e("POST", "/overrides/{id}/approvals", AP, SE),
    _e("GET", "/findings", V, SE, AU),
    _e("POST", "/grants", AO),
    _e("POST", "/incidents", IR, SE), _e("POST", "/incidents/{id}/containment", IR, SE),
    _e("GET", "/audit/events", AU, SE, IR), _e("POST", "/audit/verification", AU, SE),
    _e("GET", "/classification-levels", V, AO, SO),
    _e("POST", "/evidence-packs", AU),
    Endpoint("GET", "/health", frozenset(), public=True),
)

# Internal interfaces (plan Sections 4.4 and 5, WP-1.7): machine identities only, never people or agents.
INTERNAL_ENDPOINTS: tuple[InternalEndpoint, ...] = (
    InternalEndpoint("POST", "/internal/audit/events", "gateway"),
    InternalEndpoint("GET", "/internal/registry/view", "gateway"),
    InternalEndpoint("POST", "/internal/scan-jobs/claim", "scanner"),
    InternalEndpoint("POST", "/internal/scan-jobs/{id}/renew", "scanner"),
    InternalEndpoint("POST", "/internal/scan-jobs/{id}/result", "scanner"),
)

_BY_KEY = {(e.method, e.path): e for e in ENDPOINTS}
_INTERNAL = {(e.method, e.path): e for e in INTERNAL_ENDPOINTS}


@dataclass(frozen=True)
class RoleBinding:
    tenant: str
    user_id: str
    role: Role
    scope: tuple[str, str] | None = None   # None is tenant-wide; otherwise (resource type, resource id)
    expires_at: datetime | None = None


class RoleBindings:
    """In-memory model of the ``role_bindings`` table; the database-backed store arrives with WP-1.6."""

    def __init__(self) -> None:
        self._rows: list[RoleBinding] = []

    def add(self, b: RoleBinding) -> None:
        self._rows.append(b)

    def active(self, tenant: str, user_id: str, now: datetime, resource: tuple[str, str] | None) -> set[Role]:
        out: set[Role] = set()
        for b in self._rows:
            if b.tenant != tenant or b.user_id != user_id:
                continue
            if b.expires_at is not None and b.expires_at <= now:
                continue
            if b.scope is None or (resource is not None and b.scope == resource):
                out.add(b.role)
        return out


def authorize(principal: Principal | None, method: str, path: str, store: RoleBindings, *,
              now: datetime, resource: tuple[str, str] | None = None) -> None:
    """Return silently when allowed, raise ``Forbidden`` otherwise. ``path`` is the route template."""
    ep = _BY_KEY.get((method, path))
    if ep is not None and ep.public:
        return
    if principal is None:
        raise Forbidden()
    internal = _INTERNAL.get((method, path))
    if internal is not None:
        if principal.kind is Kind.SERVICE and principal.service == internal.service:
            return
        raise Forbidden()
    if ep is None or principal.kind is not Kind.USER or principal.tenant is None or principal.user_id is None:
        raise Forbidden()
    if store.active(principal.tenant, principal.user_id, now, resource) & ep.roles:
        return
    raise Forbidden()
