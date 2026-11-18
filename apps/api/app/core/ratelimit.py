"""Abuse protection for the PUBLIC endpoints (no session): portal identity and logo, invitation preview and acceptance,
installer download and agent enrollment.

Fixed windows per (endpoint group, client address), counted in PostgreSQL (novrsoc.rate_limit_hit) so every API worker
shares the same counters. The count is committed in its OWN transaction before the endpoint runs: a request that then
fails (a guessed invitation token, an expired installer link) still counts. The client address is the one uvicorn
derives from X-Forwarded-For sent by the trusted proxy (FORWARDED_ALLOW_IPS); only a digest of it is stored.
Exceeding a limit answers 429 with Retry-After; the first refusal of each window is audited.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from fastapi import Depends, Request
from sqlalchemy import text

from app.audit import service as audit
from app.core.config import Settings, get_settings
from app.core.errors import ApiError
from app.db.session import transaction

log = logging.getLogger("novrsoc.ratelimit")


@dataclass(frozen=True)
class Limit:
    hits: int
    window_seconds: int


# Generous for people, tight for guessing: a portal page loads its identity once; an invitation is opened a few times; a
# site can enroll many endpoints from behind one NAT address (enrollment also has its own per-ticket endpoint limit).
LIMITS: dict[str, Limit] = {
    "portal": Limit(240, 60),
    "invitation": Limit(20, 600),
    "installer": Limit(30, 600),
    "enroll": Limit(120, 600),
}


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def check(request: Request, settings: Settings, group: str) -> None:
    if not settings.rate_limits_enabled:
        return
    lim = LIMITS[group]
    bucket = f"{group}:{hashlib.sha256(_client(request).encode()).hexdigest()[:32]}"
    with transaction() as conn:
        hits = conn.execute(text("SELECT novrsoc.rate_limit_hit(:b, :w)"), {"b": bucket, "w": lim.window_seconds}).scalar()
    if hits > lim.hits:
        if hits == lim.hits + 1:
            audit.record("RATE_LIMITED", "denied", actor_label="public client", resource_type="endpoint_group", resource_id=group,
                         request_id=getattr(request.state, "request_id", None), ip=_client(request),
                         details={"limit": lim.hits, "window_seconds": lim.window_seconds, "path": request.url.path})
            log.warning("rate limit reached for %s", group)
        raise ApiError(429, "rate_limited", "Too many requests from this address. Try again later.",
                       headers={"Retry-After": str(lim.window_seconds)})


def limited(group: str):
    """FastAPI dependency: count this request against `group` and refuse it beyond the limit."""
    if group not in LIMITS:
        raise ValueError(group)

    def dep(request: Request, settings: Settings = Depends(get_settings)) -> None:
        check(request, settings, group)
    return dep
