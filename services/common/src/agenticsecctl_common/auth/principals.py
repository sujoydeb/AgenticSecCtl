"""Who is calling: users, agents and platform services (FR-ID-1/2, FR-AUTH-*, CTL-23).

A token proves a client and a subject; this directory decides what kind of
principal that is. Rules that matter:

* An OAuth client belongs to exactly one thing: one agent, one platform service
  role, or the dashboard. Reusing a client for a second purpose is refused at
  registration, so credentials are never shared between agents (FR-ID-1).
* An agent's tenant comes from its registration, never from the token.
* A person's tenant comes from the token and must name a registered user;
  dashboard users must have authenticated with a second factor.
* An agent or service token can never become a user: the client decides the kind.
"""
from __future__ import annotations

import enum
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .jwt import Claims

MFA_METHODS = frozenset({"mfa", "otp", "hwk"})
SERVICES = frozenset({"gateway", "scanner"})


class IdentityError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Kind(enum.Enum):
    USER = "user"
    AGENT = "agent"
    SERVICE = "service"


@dataclass(frozen=True)
class Principal:
    kind: Kind
    subject: str
    client_id: str
    tenant: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    service: str | None = None


class IdentityDirectory:
    def __init__(self, user_clients: set[str] | frozenset[str] = frozenset(),
                 user_lookup: Callable[[str, str], str | None] | None = None):
        self._user_lookup = user_lookup  # (tenant, subject) -> user id, for services that keep users in a database
        self._lock = threading.Lock()
        self._user_clients: set[str] = set()
        self._agents: dict[str, tuple[str, str]] = {}     # client -> (tenant, agent)
        self._agent_clients: dict[tuple[str, str], str] = {}  # (tenant, agent) -> client
        self._services: dict[str, str] = {}               # client -> service role
        self._users: dict[tuple[str, str], str] = {}      # (tenant, subject) -> user id
        for c in user_clients:
            self.register_user_client(c)

    def _taken(self, client: str, *, but: str) -> bool:
        return ((but != "user" and client in self._user_clients) or (but != "agent" and client in self._agents)
                or (but != "service" and client in self._services))

    def register_user_client(self, client_id: str) -> None:
        with self._lock:
            if self._taken(client_id, but="user"):
                raise IdentityError("client-in-use")
            self._user_clients.add(client_id)

    def register_agent(self, tenant: str, client_id: str, agent_id: str) -> None:
        with self._lock:
            if self._taken(client_id, but="agent"):
                raise IdentityError("client-in-use")
            if client_id in self._agents:
                if self._agents[client_id] == (tenant, agent_id):
                    return
                raise IdentityError("client-in-use")
            if (tenant, agent_id) in self._agent_clients:
                raise IdentityError("agent-has-client")
            self._agents[client_id] = (tenant, agent_id)
            self._agent_clients[(tenant, agent_id)] = client_id

    def register_service(self, client_id: str, service: str) -> None:
        if service not in SERVICES:
            raise IdentityError("unknown-service")
        with self._lock:
            if self._taken(client_id, but="service"):
                raise IdentityError("client-in-use")
            if self._services.get(client_id) == service:
                return
            if client_id in self._services or service in self._services.values():
                raise IdentityError("service-has-client")
            self._services[client_id] = service

    def register_user(self, tenant: str, subject: str, *, user_id: str) -> None:
        with self._lock:
            self._users[(tenant, subject)] = user_id

    def resolve(self, claims: Claims) -> Principal:
        client = claims.client_id
        if client in self._agents:
            tenant, agent = self._agents[client]
            return Principal(Kind.AGENT, claims.subject, client, tenant=tenant, agent_id=agent)
        if client in self._services:
            return Principal(Kind.SERVICE, claims.subject, client, service=self._services[client])
        if client not in self._user_clients:
            raise IdentityError("unknown-client")
        tenant = claims.raw.get("tenant_id")
        if not isinstance(tenant, str) or not tenant:
            raise IdentityError("unknown-user")
        user_id = self._users.get((tenant, claims.subject))
        if user_id is None and self._user_lookup is not None:
            user_id = self._user_lookup(tenant, claims.subject)
        if user_id is None:
            raise IdentityError("unknown-user")
        amr: Any = claims.raw.get("amr")
        if not isinstance(amr, list) or not MFA_METHODS & {m for m in amr if isinstance(m, str)}:
            raise IdentityError("mfa-required")
        return Principal(Kind.USER, claims.subject, client, tenant=tenant, user_id=user_id)
