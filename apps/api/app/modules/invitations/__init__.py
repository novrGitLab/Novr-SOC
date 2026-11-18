"""Accepting an invitation (PUBLIC: the invitee has no account yet).

The invitation token is the only key. It arrives in the link's URL fragment (never sent to a server, so never in a log)
and is posted in a request BODY here. Only its SHA-256 is stored. An invitation is accepted only:
  * while it is open (not accepted, revoked or expired) and its organization is active;
  * at its organization's own portal when that organization has an enabled portal, else at the platform address;
  * for an email that has no account yet (one account per person: an existing account is given a membership by a
    NovrSOC administrator instead).
Accepting creates the account and its home membership in one database statement (novrsoc.invitation_accept).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from app import portal as portals
from app.audit import service as audit
from app.auth.deps import client_ip
from app.core.config import Settings, get_settings
from app.core.errors import ApiError
from app.core.ratelimit import limited
from app.core.security import hash_password, sha256
from app.db.session import request_connection, set_context
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.portal import InvitationAccept, InvitationAccepted, InvitationPreview, InvitationToken

MODULE = ModuleInfo(name="invitations", workstream="E", prefix="/api/v1/invitations",
                    summary="Accept an organization invitation (public; the token is the only key)")
router = APIRouter(prefix="/api/v1/invitations", tags=["invitations"], responses=ERRORS)


def _lookup(conn: Connection, token: str):
    return conn.execute(text("SELECT * FROM novrsoc.invitation_preview(:h)"), {"h": sha256(token)}).first()


def _org(conn: Connection, org_id):
    set_context(conn, org_id=org_id)       # its own organization row only (RLS), to check where it may be accepted
    return conn.execute(text("SELECT id, name, brand_display_name, portal_subdomain::text AS sub, portal_enabled, kind, status "
                             "FROM novrsoc.organizations WHERE id = :o"), {"o": org_id}).one()


def _right_place(conn: Connection, request: Request, settings: Settings, org) -> bool:
    here = portals.resolve(conn, request, settings)
    if org.portal_enabled and settings.portal_base_domain:
        return here.kind == "tenant" and here.org_id == org.id
    return here.kind == "platform"


@router.post("/preview", response_model=InvitationPreview, summary="What an invitation is for, before accepting it (public)",
             dependencies=[Depends(limited("invitation"))])
def preview(body: InvitationToken, request: Request, conn: Connection = Depends(request_connection),
            settings: Settings = Depends(get_settings)) -> InvitationPreview:
    inv = _lookup(conn, body.token)
    if inv is None:
        raise ApiError(404, "not_found", "This invitation is not valid. Ask your administrator for a new one.")
    org = _org(conn, inv.org_id)
    if not _right_place(conn, request, settings, org):
        raise ApiError(404, "not_found", "This invitation is not valid at this address. Open the link you received.")
    if inv.state != "open":
        return InvitationPreview(state=inv.state)
    return InvitationPreview(state="open", email=inv.email, role=inv.role_key, organization=org.brand_display_name or org.name,
                             expires_at=inv.expires_at)


@router.post("/accept", response_model=InvitationAccepted, status_code=201, summary="Accept an invitation: create the account (public)",
             dependencies=[Depends(limited("invitation"))])
def accept(body: InvitationAccept, request: Request, conn: Connection = Depends(request_connection),
           settings: Settings = Depends(get_settings)) -> InvitationAccepted:
    inv = _lookup(conn, body.token)
    refused = ApiError(404, "not_found", "This invitation is not valid. Ask your administrator for a new one.")
    if inv is None:
        raise refused
    org = _org(conn, inv.org_id)
    if not _right_place(conn, request, settings, org) or inv.state != "open":
        audit.record("INVITATION_REFUSED", "denied", org_id=inv.org_id, actor_label=inv.email, resource_type="invitation",
                     resource_id=str(inv.invitation_id), request_id=request.state.request_id, ip=client_ip(request),
                     details={"state": inv.state, "host": portals.request_host(request, settings)[:253]})
        raise refused
    if len(body.password.encode()) > 72:
        raise ApiError(422, "password_too_long", "Use at most 72 bytes (a long passphrase of plain words fits)")
    if body.password.strip().lower() == inv.email.lower():
        raise ApiError(422, "password_not_allowed", "Choose a password that differs from your email")
    try:
        with conn.begin_nested():
            user = conn.execute(text("SELECT novrsoc.invitation_accept(:h, :n, :p)"),
                                {"h": sha256(body.token), "n": body.display_name.strip(), "p": hash_password(body.password)}).scalar()
    except IntegrityError:
        raise ApiError(409, "account_exists", "An account with this email already exists. Ask your administrator to add it to "
                                              "the organization instead.") from None
    if user is None:                       # accepted or revoked concurrently
        raise refused
    audit.record("INVITATION_ACCEPTED", "success", org_id=inv.org_id, actor_id=user, actor_label=inv.email, resource_type="invitation",
                 resource_id=str(inv.invitation_id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"role": inv.role_key})
    return InvitationAccepted(email=inv.email, sign_in_url=portals.base_url(settings, org.sub, org.portal_enabled) + "/login")
