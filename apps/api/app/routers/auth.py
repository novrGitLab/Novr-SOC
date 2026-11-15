"""Authentication: login, logout, session info, accessible organizations."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import service as audit
from app.auth.deps import Principal, client_ip, current_principal
from app.authz.org_resolution import Membership
from app.core.config import Settings, get_settings
from app.core.errors import ApiError
from app.core.security import hash_password, new_token, sha256, verify_password
from app.db.session import request_connection, set_context, transaction
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.platform import (LoginRequest, LoginResponse, MembershipSummary, OrgList, OrgSummary,
                                           PasswordChangeRequest, SessionInfo, UserSummary)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"], responses=ERRORS)
orgs_router = APIRouter(prefix="/api/v1/orgs", tags=["organizations"], responses=ERRORS)

_INVALID = ApiError(401, "invalid_credentials", "Invalid email or password")


def _org(m: Membership) -> OrgSummary:
    return OrgSummary(id=m.org_id, slug=m.org_slug, name=m.org_name)


def session_info(p: Principal, conn: Connection) -> SessionInfo:
    active = next((m for m in p.memberships if m.org_id == p.org_id), None)
    if active is not None:
        active_org = _org(active)
    else:  # super_admin acting on an organization without a membership
        r = conn.execute(text("SELECT id, slug, name FROM novrsoc.organizations WHERE id = :id"), {"id": p.org_id}).one()
        active_org = OrgSummary(id=r.id, slug=str(r.slug), name=r.name)
    return SessionInfo(
        user=UserSummary(id=p.user_id, email=p.email, display_name=p.display_name), role=p.role,  # type: ignore[arg-type]
        home_org=_org(p.home), active_org=active_org, cross_org=p.cross_org, permissions=sorted(p.permissions),
        memberships=[MembershipSummary(org=_org(m), role=m.role, access_scope=m.access_scope)  # type: ignore[arg-type]
                     for m in p.memberships], password_change_required=p.password_change_required)


@router.post("/login", response_model=LoginResponse, summary="Sign in (sets an httpOnly session cookie)")
def login(body: LoginRequest, request: Request, response: Response, conn: Connection = Depends(request_connection),
          settings: Settings = Depends(get_settings)) -> LoginResponse:
    email = body.email.strip().lower()
    row = conn.execute(text("SELECT * FROM novrsoc.auth_user_for_login(:e)"), {"e": email}).first()
    ok = verify_password(body.password, row.password_hash if row else None)
    locked = bool(row and row.locked_until is not None and row.locked_until > datetime.now(timezone.utc))
    if not row or not ok or locked or row.status != "active":
        reason = "unknown_account" if not row else "locked" if locked else "disabled" if row.status != "active" else "bad_password"
        if row and not locked and row.status == "active":
            with transaction() as own:  # its own transaction: the failure counts even though this request fails
                own.execute(text("SELECT novrsoc.auth_record_login(:u, false, :m, :l)"),
                            {"u": row.user_id, "m": settings.login_max_failures, "l": settings.login_lockout_minutes})
        audit.record("LOGIN_FAILED", "denied", actor_id=row.user_id if row else None, actor_label=email,
                     resource_type="session", request_id=request.state.request_id, ip=client_ip(request),
                     details={"reason": reason})
        raise _INVALID
    conn.execute(text("SELECT novrsoc.auth_record_login(:u, true, :m, :l)"),
                 {"u": row.user_id, "m": settings.login_max_failures, "l": settings.login_lockout_minutes})
    token, csrf = new_token(), new_token()
    conn.execute(text("SELECT novrsoc.auth_create_session(:u, :t, :c, :ttl)"),
                 {"u": row.user_id, "t": sha256(token), "c": sha256(csrf), "ttl": settings.session_ttl_minutes})

    # Build the session view exactly as an authenticated request would see it (home organization).
    set_context(conn, user_id=row.user_id)
    from app.authz.org_resolution import load_memberships
    from app.authz.catalog import permissions_for
    ms = load_memberships(conn)
    home = next((m for m in ms if m.access_scope == "home"), None)
    if home is None:
        raise ApiError(403, "no_home_org", "This account has no home organization")
    u = conn.execute(text("SELECT email, display_name, password_change_required FROM novrsoc.users WHERE id = :id"),
                     {"id": row.user_id}).one()
    p = Principal(user_id=row.user_id, email=str(u.email), display_name=u.display_name, role=home.role, home=home,
                  memberships=ms, org_id=home.org_id, cross_org=False, permissions=permissions_for(home.role),
                  password_change_required=bool(u.password_change_required))
    secure, max_age = settings.session_cookie_secure, settings.session_ttl_minutes * 60
    response.set_cookie(settings.session_cookie_name, token, max_age=max_age, httponly=True, secure=secure,
                        samesite="lax", path="/")
    response.set_cookie(settings.csrf_cookie_name, csrf, max_age=max_age, httponly=False, secure=secure,
                        samesite="strict", path="/")
    audit.record("LOGIN_SUCCEEDED", "success", org_id=home.org_id, actor_id=row.user_id, actor_label=email,
                 resource_type="session", request_id=request.state.request_id, ip=client_ip(request))
    return LoginResponse(session=session_info(p, conn), csrf_token=csrf)


@router.post("/logout", status_code=204, summary="Revoke the current session")
def logout(request: Request, response: Response, p: Principal = Depends(current_principal),
           conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> Response:
    token = request.cookies.get(settings.session_cookie_name, "")
    conn.execute(text("SELECT novrsoc.auth_revoke_session(:h)"), {"h": sha256(token)})
    audit.record("LOGOUT", "success", org_id=p.home.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="session", request_id=request.state.request_id, ip=client_ip(request))
    response = Response(status_code=204)
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")
    return response


@router.post("/password", status_code=204, summary="Change your password (other sessions are revoked)")
def change_password(body: PasswordChangeRequest, request: Request, p: Principal = Depends(current_principal),
                    conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> Response:
    row = conn.execute(text("SELECT * FROM novrsoc.auth_user_for_login(:e)"), {"e": p.email}).first()
    if row is None or not verify_password(body.current_password, row.password_hash):
        if row is not None:
            with transaction() as own:  # a wrong current password counts towards the lockout like a failed sign-in
                own.execute(text("SELECT novrsoc.auth_record_login(:u, false, :m, :l)"),
                            {"u": row.user_id, "m": settings.login_max_failures, "l": settings.login_lockout_minutes})
        audit.record("PASSWORD_CHANGE_FAILED", "denied", org_id=p.home.org_id, actor_id=p.user_id, actor_label=p.email,
                     resource_type="user", resource_id=str(p.user_id), request_id=request.state.request_id,
                     ip=client_ip(request), details={"reason": "bad_current_password"})
        raise ApiError(400, "invalid_current_password", "The current password is not correct")
    if len(body.new_password.encode()) > 72:
        raise ApiError(422, "password_too_long", "Use at most 72 bytes (a long passphrase of plain words fits)")
    if body.new_password == body.current_password or body.new_password.strip().lower() == p.email.lower():
        raise ApiError(422, "password_not_changed", "Choose a new password that differs from the current one and the email")
    token = request.cookies.get(settings.session_cookie_name, "")
    conn.execute(text("SELECT novrsoc.auth_change_password(:h, :k)"),
                 {"h": hash_password(body.new_password), "k": sha256(token)})
    audit.record("PASSWORD_CHANGED", "success", org_id=p.home.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="user", resource_id=str(p.user_id), request_id=request.state.request_id,
                 ip=client_ip(request), details={"was_temporary": p.password_change_required})
    return Response(status_code=204)


@router.get("/me", response_model=SessionInfo, summary="The signed-in user, role, active organization and permissions")
def me(p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> SessionInfo:
    return session_info(p, conn)


@orgs_router.get("", response_model=OrgList, summary="Organizations the caller may act on (X-Org-Id values)")
def list_orgs(p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> OrgList:
    if p.role == "super_admin":
        rows = conn.execute(text("SELECT id, slug, name FROM novrsoc.organizations WHERE status = 'active' ORDER BY name")).all()
        return OrgList(items=[OrgSummary(id=r.id, slug=str(r.slug), name=r.name) for r in rows], all_organizations=True)
    allowed = {"home"} | ({"operations"} if p.role in ("soc_manager", "analyst") else set()) | (
        {"reporting"} if p.role == "executive" else set())
    return OrgList(items=[_org(m) for m in p.memberships if m.access_scope in allowed], all_organizations=False)
