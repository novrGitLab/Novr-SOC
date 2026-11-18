"""Request authentication and authorisation dependencies.

Human callers: opaque session cookie (httpOnly) + double-submit CSRF header on unsafe methods.
Machine callers: "Authorization: Bearer nsk_<id>.<secret>"; the organization (and site) come from the
service identity record, never from the request.

Order inside one request transaction:
  0. portal of the request host (app.portal)  -> platform / one organization's portal / unknown
  1. session lookup (SECURITY DEFINER)        -> user id; the session must belong to THIS host's portal
  2. set app.user_id (+ app.platform_admin for super_admin)
  3. memberships (RLS: own rows)              -> home role
  4. organization resolution (X-Org-Id)       -> set app.org_id
  5. permission check against the home role
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from fastapi import Depends, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import service as audit
from app.authz.catalog import permissions_for
from app.authz.org_resolution import ORG_HEADER, Membership, load_memberships, resolve
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, forbidden, unauthenticated
from app.core.security import digests_equal, parse_machine_credential, sha256
from app.db.session import request_connection, set_context
from app import portal as portals

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_HEADER = "X-CSRF-Token"


@dataclass
class Principal:
    user_id: uuid.UUID
    email: str
    display_name: str
    role: str
    home: Membership
    memberships: list[Membership]
    org_id: uuid.UUID
    cross_org: bool
    permissions: frozenset[str] = field(default_factory=frozenset)
    password_change_required: bool = False

    def has(self, permission: str) -> bool:
        return permission in self.permissions


def _is_uuid(v: str) -> bool:
    try:
        uuid.UUID(v.strip())
        return True
    except ValueError:
        return False


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# Reachable while the account still has a temporary password (users.password_change_required).
PASSWORD_CHANGE_PATHS = frozenset({"/api/v1/auth/me", "/api/v1/auth/password", "/api/v1/auth/logout"})


def _authenticate_session(request: Request, conn: Connection, settings: Settings) -> tuple[uuid.UUID, str, str, bool]:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise unauthenticated()
    row = conn.execute(text("SELECT session_id, user_id, csrf_hash, portal_org_id FROM novrsoc.auth_session_portal(:h)"),
                       {"h": sha256(token)}).first()
    if not row:
        raise unauthenticated("Session expired or invalid")
    here = portals.resolve(conn, request, settings)
    request.state.portal = here
    expected = here.org_id if here.kind == "tenant" else None
    if here.kind == "unknown" or row.portal_org_id != expected:
        # A session is valid only on the host it was created on: a copied cookie or a forged Host never moves it.
        audit.record("SESSION_HOST_MISMATCH", "denied", org_id=row.portal_org_id, actor_id=row.user_id, resource_type="session",
                     resource_id=str(row.session_id), request_id=request.state.request_id, ip=client_ip(request),
                     details={"host": here.host[:253], "portal": here.kind, "path": request.url.path})
        raise unauthenticated("This session does not belong to this address. Sign in here.")
    if request.method.upper() in UNSAFE:
        presented = request.headers.get(CSRF_HEADER, "")
        if not presented or not digests_equal(sha256(presented), bytes(row.csrf_hash)):
            raise ApiError(403, "csrf_failed", "Missing or invalid CSRF token")
    set_context(conn, user_id=row.user_id)
    u = conn.execute(text("SELECT email, display_name, password_change_required FROM novrsoc.users WHERE id = :id"),
                     {"id": row.user_id}).one()
    if u.password_change_required and request.url.path not in PASSWORD_CHANGE_PATHS:
        raise ApiError(403, "password_change_required", "Change the temporary password before using NovrSOC")
    return row.user_id, str(u.email), u.display_name, bool(u.password_change_required)


def current_principal(request: Request, conn: Connection = Depends(request_connection),
                      settings: Settings = Depends(get_settings)) -> Principal:
    user_id, email, display, must_change = _authenticate_session(request, conn, settings)
    memberships = load_memberships(conn)
    home = next((m for m in memberships if m.access_scope == "home"), None)
    if home is not None and home.role == "super_admin":
        set_context(conn, platform_admin=True)

    def audit_denied(target: uuid.UUID, reason: str) -> None:
        audit.record("CROSS_ORG_DENIED", "denied", org_id=home.org_id if home else None, actor_id=user_id,
                     actor_label=email, resource_type="organization", resource_id=str(target),
                     request_id=request.state.request_id, ip=client_ip(request),
                     details={"reason": reason, "method": request.method, "path": request.url.path})

    here = request.state.portal
    requested = request.headers.get(ORG_HEADER)
    if here.kind == "tenant":
        # An organization portal shows that organization only: no switch, whatever the role or the header says.
        if home is None or home.org_id != here.org_id:
            raise unauthenticated("This session does not belong to this address. Sign in here.")
        if requested and requested.strip() not in ("", str(here.org_id)):
            audit_denied(uuid.UUID(int=0) if not _is_uuid(requested) else uuid.UUID(requested.strip()), "organization switch on a portal")
            raise forbidden("An organization portal shows its own organization only")
        requested = None
    res = resolve(conn, home=home, memberships=memberships, requested=requested,
                  method=request.method, audit_denied=audit_denied)
    set_context(conn, org_id=res.org_id)
    if res.cross_org:
        audit.record("CROSS_ORG_ACCESS", "success", org_id=res.org_id, actor_id=user_id, actor_label=email,
                     resource_type="organization", resource_id=str(res.org_id),
                     request_id=request.state.request_id, ip=client_ip(request),
                     details={"home_org_id": str(home.org_id), "role": home.role,  # type: ignore[union-attr]
                              "method": request.method, "path": request.url.path})
    p = Principal(user_id=user_id, email=email, display_name=display, role=home.role,  # type: ignore[union-attr]
                  home=home, memberships=memberships, org_id=res.org_id, cross_org=res.cross_org,  # type: ignore[arg-type]
                  permissions=permissions_for(home.role),  # type: ignore[union-attr]
                  password_change_required=must_change)
    request.state.principal = p
    return p


def require(permission: str):
    def dep(request: Request, p: Principal = Depends(current_principal)) -> Principal:
        if not p.has(permission):
            audit.record("PERMISSION_DENIED", "denied", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                         resource_type="permission", resource_id=permission, request_id=request.state.request_id,
                         ip=client_ip(request), details={"role": p.role, "path": request.url.path})
            raise forbidden("Insufficient permissions", {"required": permission})
        return p
    return dep


# ---------------------------------------------------------------- machine identities
@dataclass(frozen=True)
class ServicePrincipal:
    identity_id: uuid.UUID
    org_id: uuid.UUID
    site_id: uuid.UUID | None
    kind: str
    scopes: frozenset[str]


def current_service(request: Request, conn: Connection = Depends(request_connection)) -> ServicePrincipal:
    auth = request.headers.get("Authorization", "")
    parsed = parse_machine_credential(auth[7:]) if auth.lower().startswith("bearer ") else None
    if parsed is None:
        raise unauthenticated("Machine credential required")
    ident_id, presented = parsed
    row = conn.execute(text("SELECT * FROM novrsoc.auth_service_identity(:id)"), {"id": ident_id}).first()
    ok = bool(row) and digests_equal(presented, bytes(row.secret_hash)) and bool(row.usable)
    if not ok:
        audit.record("SERVICE_AUTH_FAILED", "denied", org_id=row.org_id if row else None, actor_type="service",
                     actor_id=ident_id, resource_type="service_identity", resource_id=str(ident_id),
                     request_id=request.state.request_id, ip=client_ip(request),
                     details={"reason": "unknown" if not row else ("revoked_or_expired" if not row.usable else "bad_secret")})
        raise unauthenticated("Invalid machine credential")
    conn.execute(text("SELECT novrsoc.auth_touch_service_identity(:id)"), {"id": ident_id})
    set_context(conn, org_id=row.org_id)
    return ServicePrincipal(row.id, row.org_id, row.site_id, row.kind, frozenset(row.scopes or []))
