"""Internal service connectors: shared building blocks.

Architecture rule: Browser -> Next.js -> FastAPI -> (these connectors) -> internal services.
The web app NEVER reaches Wazuh, the indexer, Ollama, Greenbone or PostgreSQL directly
(tests/test_architecture.py enforces it). Connectors live only in the API and its workers.

Every connector:
  * is configured from environment variables by NAME (values never appear in errors or logs);
  * talks TLS with verification always on (app.core.tls.service_tls; pin with <PREFIX>_CA_CERT);
  * takes an explicit OrgScope for any tenant data, so an unscoped call is impossible;
  * maps failures to the honest error types below (unconfigured / unavailable / rejected / timeout).
Phase 2.5: interfaces, configuration and scope logic only. No connector contacts a real service.
"""
from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.core.tls import ServiceTls, service_tls

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class ConnectorError(Exception):
    """Base class. Messages name settings and services, never secret values."""


class ConnectorUnconfigured(ConnectorError):
    pass


class ConnectorUnavailable(ConnectorError):
    pass


class ConnectorRejected(ConnectorError):
    """The service refused the request (authentication, authorisation, validation)."""


class ConnectorTimeout(ConnectorError):
    pass


class ScopeViolation(ConnectorError):
    """A result or request crossed the caller's organization scope. Always fatal for the request."""


@dataclass(frozen=True)
class OrgScope:
    """Which slice of SHARED infrastructure (one Wazuh manager serves many organizations) belongs to one
    organization. Built server-side from the organization's group/source map, never from the request.
    An empty scope matches nothing (fail closed)."""
    org_id: uuid.UUID
    wazuh_agent_groups: frozenset[str] = field(default_factory=frozenset)
    wazuh_syslog_sources: frozenset[str] = field(default_factory=frozenset)

    @property
    def empty(self) -> bool:
        return not self.wazuh_agent_groups and not self.wazuh_syslog_sources


@dataclass(frozen=True)
class Endpoint:
    name: str
    base_url: str
    tls: ServiceTls | None
    timeout_seconds: float
    credential_names: tuple[str, ...]


def load_endpoint(prefix: str, env: Mapping[str, str], *, app_env: str, credential_names: tuple[str, ...] = (),
                  default_timeout: float = 10.0, allow_loopback_http: bool = False) -> Endpoint:
    """Validate a service endpoint from environment variables. Raises ConnectorUnconfigured naming the
    missing or invalid settings. https is required; plain http is accepted only for a loopback proxy in
    development/test when explicitly allowed."""
    url = (env.get(f"{prefix}_URL") or "").strip().rstrip("/")
    if not url:
        raise ConnectorUnconfigured(f"{prefix}_URL is not set")
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme == "http":
        if not (allow_loopback_http and host in LOOPBACK and app_env in ("development", "test")):
            raise ConnectorUnconfigured(f"{prefix}_URL must use https")
    elif parts.scheme != "https":
        raise ConnectorUnconfigured(f"{prefix}_URL must use https")
    if not host or parts.username or parts.password:
        raise ConnectorUnconfigured(f"{prefix}_URL must be a host URL without embedded credentials")
    missing = [n for n in credential_names if not (env.get(n) or "").strip()]
    if missing:
        raise ConnectorUnconfigured(f"missing credential settings: {', '.join(missing)}")
    try:
        timeout = float(env.get(f"{prefix}_TIMEOUT_SECONDS") or default_timeout)
    except ValueError:
        raise ConnectorUnconfigured(f"{prefix}_TIMEOUT_SECONDS must be a number") from None
    if not 0.5 <= timeout <= 300:
        raise ConnectorUnconfigured(f"{prefix}_TIMEOUT_SECONDS must be between 0.5 and 300")
    tls = service_tls(prefix, env) if parts.scheme == "https" else None
    return Endpoint(name=prefix, base_url=url, tls=tls, timeout_seconds=timeout, credential_names=credential_names)


@dataclass(frozen=True)
class ConnectorHealth:
    name: str
    configured: bool
    reachable: bool | None  # None = not checked (Phase 2.5 never checks real services)
    tls_verified: bool
    detail: str = ""


def ip_in_networks(ip: str, cidrs: list[str] | tuple[str, ...]) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)
