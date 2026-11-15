"""Which organization a request acts on. Port of legacy lib/resolveOrg.ts (approved access policy).

A role alone never establishes access to an organization:
  super_admin          any existing organization named in X-Org-Id (audited CROSS_ORG_ACCESS).
  soc_manager, analyst own (home) organization, or one with an 'operations' membership; else 403,
                       audited CROSS_ORG_DENIED.
  executive            own organization; X-Org-Id honoured only with a 'reporting' membership and only
                       for GET/HEAD (a change is 403, audited). Without one the header is ignored.
  portal_user, unknown always the home organization; any X-Org-Id is ignored.
A malformed or unknown X-Org-Id from a role that may switch is 400. There is no "all organizations"
mode and no default organization: an account without a home membership is refused (403).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.core.errors import ApiError, forbidden

ORG_HEADER = "X-Org-Id"
SAFE_METHODS = {"GET", "HEAD"}


@dataclass(frozen=True)
class Membership:
    org_id: uuid.UUID
    org_slug: str
    org_name: str
    role: str
    access_scope: str


@dataclass(frozen=True)
class Resolution:
    org_id: uuid.UUID
    cross_org: bool


def load_memberships(conn: Connection) -> list[Membership]:
    """The caller's memberships (RLS: rows where user_id = app.user_id)."""
    rows = conn.execute(text("""
        SELECT m.org_id, o.slug, o.name, m.role_key, m.access_scope
          FROM novrsoc.memberships m JOIN novrsoc.organizations o ON o.id = m.org_id
         WHERE m.user_id = novrsoc.app_user() AND o.status = 'active'
         ORDER BY (m.access_scope = 'home') DESC, o.name""")).all()
    return [Membership(r[0], str(r[1]), r[2], r[3], r[4]) for r in rows]


def resolve(conn: Connection, *, home: Membership | None, memberships: list[Membership], requested: str | None,
            method: str, audit_denied) -> Resolution:
    if home is None:
        raise forbidden("No home organization on this account; tenant data cannot be accessed")
    role = home.role
    req = (requested or "").strip()
    if not req:
        return Resolution(home.org_id, False)
    may_switch = role in ("super_admin", "soc_manager", "analyst", "executive")
    if not may_switch:
        return Resolution(home.org_id, False)  # portal_user / unknown: header ignored
    try:
        target = uuid.UUID(req)
    except ValueError:
        if role == "executive":
            return Resolution(home.org_id, False)
        raise ApiError(400, "invalid_org", "X-Org-Id must be an organization id (UUID)")
    if target == home.org_id:
        return Resolution(home.org_id, False)

    by_org = {m.org_id: m for m in memberships}
    if role == "executive":
        m = by_org.get(target)
        if not m or m.access_scope != "reporting":
            return Resolution(home.org_id, False)  # legacy behaviour: header ignored without an assignment
        if method.upper() not in SAFE_METHODS:
            audit_denied(target, "executive reporting access is read-only")
            raise forbidden("Reporting access to another organization is read-only")
        return Resolution(target, True)

    if role == "super_admin":
        exists = conn.execute(text("SELECT 1 FROM novrsoc.organizations WHERE id = :id AND status = 'active'"),
                              {"id": target}).first()
        if not exists:
            raise ApiError(400, "unknown_org", "Unknown organization")
        return Resolution(target, True)

    m = by_org.get(target)  # soc_manager, analyst
    if not m or m.access_scope != "operations":
        audit_denied(target, f"{role} is not assigned to the organization")
        raise forbidden("You are not assigned to this organization")
    return Resolution(target, True)
