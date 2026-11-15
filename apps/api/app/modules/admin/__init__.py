"""Tenant administration (pilot): organizations, users and memberships, service identities, backup history.

Organizations, users and memberships are managed by platform administrators (super_admin; the database enforces it
through the platform-admin RLS context and two SECURITY DEFINER helpers). Service identities are managed per
organization with service_identities:manage; the credential is returned once and only its hash is stored. A
forwarder identity belongs to the platform organization; each kind may only hold its own scope.
"""
from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError, InternalError, ProgrammingError

from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.core.errors import ApiError, not_found
from app.core.security import hash_password, new_machine_credential
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.platform import (AdminOrg, AdminOrgCreate, AdminOrgList, AdminUser, AdminUserCreate, AdminUserCreated,
                                           AdminUserList, BackupRunList, BackupRunView, ServiceIdentityCreate, ServiceIdentityIssued,
                                           ServiceIdentityList, ServiceIdentityView, UserStatusUpdate)

MODULE = ModuleInfo(name="admin", workstream="E", prefix="/api/v1/admin",
                    summary="Organizations, users, memberships, service identities and backup history")
router = APIRouter(prefix="/api/v1/admin", tags=["admin"], responses=ERRORS)

KIND_SCOPES = {"forwarder": {"alerts:ingest"}, "vms_worker": {"vms:worker"}, "ti_feeder": {"intel:ingest"},
               "collector": {"telemetry:ingest"}, "email_gateway": {"email:verdicts"}, "backup_agent": {"backups:report"}}


def _audit(p: Principal, request: Request, action: str, rtype: str, rid: str, details: dict | None = None) -> None:
    audit.record(action, "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type=rtype, resource_id=rid,
                 request_id=request.state.request_id, ip=client_ip(request), details=details or {})


# ---------------------------------------------------------------- organizations
def _org(r) -> AdminOrg:
    return AdminOrg(id=r.id, slug=str(r.slug), name=r.name, kind=r.kind, status=r.status, created_at=r.created_at)


@router.get("/organizations", response_model=AdminOrgList, summary="All organizations (platform administrators)")
def list_orgs(p: Principal = Depends(require("users:manage")), conn: Connection = Depends(request_connection)) -> AdminOrgList:
    return AdminOrgList(items=[_org(r) for r in conn.execute(text("SELECT * FROM novrsoc.organizations ORDER BY kind DESC, name"))])


@router.post("/organizations", response_model=AdminOrg, status_code=201, summary="Create a client organization")
def create_org(body: AdminOrgCreate, request: Request, p: Principal = Depends(require("users:manage")),
               conn: Connection = Depends(request_connection)) -> AdminOrg:
    try:
        with conn.begin_nested():
            r = conn.execute(text("INSERT INTO novrsoc.organizations (slug, name, kind) VALUES (:s, :n, 'client') RETURNING *"),
                             {"s": body.slug, "n": body.name}).one()
    except IntegrityError:
        raise ApiError(409, "conflict", "An organization with this slug already exists")
    _audit(p, request, "ORG_CREATED", "organization", str(r.id), {"slug": body.slug})
    return _org(r)


# ---------------------------------------------------------------- users and memberships (active organization)
_USER_SQL = """SELECT u.id, u.email, u.display_name, u.status, u.last_login_at, (u.locked_until > now()) AS locked,
                      m.role_key, m.access_scope
               FROM novrsoc.memberships m JOIN novrsoc.users u ON u.id = m.user_id WHERE m.org_id = :o"""


def _user(r) -> AdminUser:
    return AdminUser(id=r.id, email=str(r.email), display_name=r.display_name, status=r.status, role=r.role_key,
                     access_scope=r.access_scope, locked=bool(r.locked), last_login_at=r.last_login_at)


@router.get("/users", response_model=AdminUserList, summary="Users with a membership in the active organization")
def list_users(p: Principal = Depends(require("users:manage")), conn: Connection = Depends(request_connection)) -> AdminUserList:
    return AdminUserList(items=[_user(r) for r in conn.execute(text(_USER_SQL + " ORDER BY u.email"), {"o": p.org_id})])


@router.post("/users", response_model=AdminUserCreated, status_code=201, summary="Create a user in the active organization")
def create_user(body: AdminUserCreate, request: Request, p: Principal = Depends(require("users:manage")),
                conn: Connection = Depends(request_connection)) -> AdminUserCreated:
    kind = conn.execute(text("SELECT kind FROM novrsoc.organizations WHERE id = :o"), {"o": p.org_id}).scalar()
    if body.role == "super_admin" and kind != "platform":
        raise ApiError(422, "validation_error", "super_admin exists only in the platform organization")
    password = secrets.token_urlsafe(18)
    try:
        with conn.begin_nested():
            uid = conn.execute(text("SELECT novrsoc.admin_create_user(:e, :n, :h)"),
                               {"e": body.email.lower(), "n": body.display_name, "h": hash_password(password)}).scalar()
            conn.execute(text("""INSERT INTO novrsoc.memberships (user_id, org_id, role_key, access_scope) VALUES (:u, :o, :r, :s)"""),
                         {"u": uid, "o": p.org_id, "r": body.role, "s": body.access_scope})
    except IntegrityError:
        raise ApiError(409, "conflict", "A user with this email already exists")
    _audit(p, request, "USER_CREATED", "user", str(uid), {"role": body.role})
    return AdminUserCreated(user=_user(conn.execute(text(_USER_SQL + " AND u.id = :u"), {"o": p.org_id, "u": uid}).one()),
                            temporary_password=password)


@router.post("/users/{user_id}/status", response_model=AdminUser, summary="Disable or re-enable a user (sessions revoked on disable)")
def set_status(user_id: uuid.UUID, body: UserStatusUpdate, request: Request, p: Principal = Depends(require("users:manage")),
               conn: Connection = Depends(request_connection)) -> AdminUser:
    if conn.execute(text(_USER_SQL + " AND u.id = :u"), {"o": p.org_id, "u": user_id}).first() is None:
        raise not_found("User not found in this organization")
    try:
        with conn.begin_nested():
            conn.execute(text("SELECT novrsoc.admin_set_user_status(:u, :s)"), {"u": user_id, "s": body.status})
    except (InternalError, ProgrammingError) as e:
        raise ApiError(409, "conflict", "You cannot change your own status" if "own status" in str(e) else "Not allowed")
    _audit(p, request, "USER_STATUS_CHANGED", "user", str(user_id), {"status": body.status})
    return _user(conn.execute(text(_USER_SQL + " AND u.id = :u"), {"o": p.org_id, "u": user_id}).one())


@router.post("/users/{user_id}/reset-password", response_model=AdminUserCreated,
             summary="Issue a new temporary password (shown once; sessions revoked; must be changed at sign-in)")
def reset_password(user_id: uuid.UUID, request: Request, p: Principal = Depends(require("users:manage")),
                   conn: Connection = Depends(request_connection)) -> AdminUserCreated:
    if conn.execute(text(_USER_SQL + " AND u.id = :u"), {"o": p.org_id, "u": user_id}).first() is None:
        raise not_found("User not found in this organization")
    password = secrets.token_urlsafe(18)
    try:
        with conn.begin_nested():
            conn.execute(text("SELECT novrsoc.admin_reset_password(:u, :h)"), {"u": user_id, "h": hash_password(password)})
    except (InternalError, ProgrammingError) as e:
        raise ApiError(409, "conflict", "Change your own password under Account" if "own password" in str(e) else "Not allowed")
    _audit(p, request, "USER_PASSWORD_RESET", "user", str(user_id), {})
    return AdminUserCreated(user=_user(conn.execute(text(_USER_SQL + " AND u.id = :u"), {"o": p.org_id, "u": user_id}).one()),
                            temporary_password=password)


# ---------------------------------------------------------------- service identities (active organization)
def _identity(r) -> ServiceIdentityView:
    return ServiceIdentityView(id=r.id, kind=r.kind, name=r.name, scopes=list(r.scopes), status=r.status, site_id=r.site_id,
                               created_at=r.created_at, last_used_at=r.last_used_at, revoked_at=r.revoked_at)


@router.get("/service-identities", response_model=ServiceIdentityList, summary="Machine identities of the active organization")
def list_identities(p: Principal = Depends(require("service_identities:manage")),
                    conn: Connection = Depends(request_connection)) -> ServiceIdentityList:
    return ServiceIdentityList(items=[_identity(r) for r in conn.execute(text("SELECT * FROM novrsoc.service_identities ORDER BY created_at DESC"))])


@router.post("/service-identities", response_model=ServiceIdentityIssued, status_code=201,
             summary="Issue a machine credential (shown once)")
def issue_identity(body: ServiceIdentityCreate, request: Request, p: Principal = Depends(require("service_identities:manage")),
                   conn: Connection = Depends(request_connection)) -> ServiceIdentityIssued:
    if not set(body.scopes) <= KIND_SCOPES[body.kind]:
        raise ApiError(422, "validation_error", f"A {body.kind} identity may only hold: {', '.join(sorted(KIND_SCOPES[body.kind]))}")
    kind = conn.execute(text("SELECT kind FROM novrsoc.organizations WHERE id = :o"), {"o": p.org_id}).scalar()
    if body.kind == "forwarder" and kind != "platform":
        raise ApiError(422, "validation_error", "A forwarder identity belongs to the platform organization")
    ident = uuid.uuid4()
    token, secret_hash = new_machine_credential(ident)
    try:
        with conn.begin_nested():
            r = conn.execute(text("""INSERT INTO novrsoc.service_identities (id, org_id, site_id, kind, name, secret_hash, scopes, created_by)
                                     VALUES (:i, :o, :s, :k, :n, :h, :sc, :u) RETURNING *"""),
                             {"i": ident, "o": p.org_id, "s": body.site_id, "k": body.kind, "n": body.name, "h": secret_hash,
                              "sc": body.scopes, "u": p.user_id}).one()
    except IntegrityError:
        raise ApiError(422, "validation_error", "The site must belong to the active organization")
    _audit(p, request, "SERVICE_IDENTITY_ISSUED", "service_identity", str(ident), {"kind": body.kind, "scopes": body.scopes})
    return ServiceIdentityIssued(identity=_identity(r), credential=token)


@router.post("/service-identities/{identity_id}/revoke", response_model=ServiceIdentityView, summary="Revoke a machine credential")
def revoke_identity(identity_id: uuid.UUID, request: Request, p: Principal = Depends(require("service_identities:manage")),
                    conn: Connection = Depends(request_connection)) -> ServiceIdentityView:
    r = conn.execute(text("""UPDATE novrsoc.service_identities SET status = 'revoked', revoked_at = now()
                             WHERE id = :i AND status = 'active' RETURNING *"""), {"i": identity_id}).first()
    if r is None:
        raise not_found("Active identity not found")
    _audit(p, request, "SERVICE_IDENTITY_REVOKED", "service_identity", str(identity_id))
    return _identity(r)


# ---------------------------------------------------------------- backups (platform)
@router.get("/backups", response_model=BackupRunList, summary="Backup runs and their latest restore drill")
def list_backups(p: Principal = Depends(require("backups:read")), conn: Connection = Depends(request_connection)) -> BackupRunList:
    rows = conn.execute(text("""SELECT b.*, d.status AS drill_status, d.finished_at AS drill_at FROM novrsoc.backup_runs b
                                LEFT JOIN LATERAL (SELECT status, finished_at FROM novrsoc.restore_drills r WHERE r.backup_id = b.id
                                                   ORDER BY finished_at DESC LIMIT 1) d ON true
                                ORDER BY b.started_at DESC LIMIT 100""")).all()
    return BackupRunList(items=[BackupRunView(id=r.id, kind=r.kind, started_at=r.started_at, finished_at=r.finished_at, status=r.status,
                                              target=r.target, size_bytes=r.size_bytes, sha256=r.sha256, encrypted=r.encrypted, note=r.note,
                                              last_drill_status=r.drill_status, last_drill_at=r.drill_at) for r in rows])


# ================================================================ consolidation: billing, exports, teams, analytics, health
import csv as _csv  # noqa: E402
import hashlib as _hashlib  # noqa: E402
import io as _io  # noqa: E402
import json as _json  # noqa: E402
from datetime import datetime as _dt, timedelta as _td, timezone as _tz  # noqa: E402

from fastapi import Query as _Query  # noqa: E402
from fastapi.responses import Response as _Response  # noqa: E402

from app.connectors import registry as _registry  # noqa: E402
from app.core.config import Settings as _Settings, get_settings as _get_settings  # noqa: E402
from novrsoc_contracts.v1.administration import (BillingOverview, BillingPlanCreate, BillingPlanUpdate, BillingPlanView,  # noqa: E402
                                                 ComponentHealth, DataExportCreate, DataExportList, DataExportView, MembershipGrant,
                                                 MembershipList, MembershipView, OnboardingStatus, OrgAnalyticsRow, OrgBillingRow,
                                                 PlatformAnalytics, PlatformHealth, QuarantineSummary, SubscriptionSet, TeamCreate,
                                                 TeamList, TeamMemberAdd, TeamMemberView, TeamView)
from novrsoc_contracts.v1.common import ActorRef as _ActorRef  # noqa: E402

EXPORT_MAX_ROWS = 50_000
_NOW = lambda: _dt.now(_tz.utc)  # noqa: E731


# ---------------------------------------------------------------- billing (platform)
def _plan(r) -> BillingPlanView:
    return BillingPlanView(id=r.id, code=r.code, name=r.name, description=r.description, price_minor=r.price_minor, currency=r.currency,
                           billing_interval=r.billing_interval, max_assets=r.max_assets, max_users=r.max_users, features=list(r.features),
                           active=r.active, created_at=r.created_at)


@router.get("/billing", response_model=BillingOverview, summary="Plans, subscriptions and usage (no payment provider is configured)")
def billing(p: Principal = Depends(require("billing:manage")), conn: Connection = Depends(request_connection)) -> BillingOverview:
    plans = [_plan(r) for r in conn.execute(text("SELECT * FROM novrsoc.billing_plans ORDER BY active DESC, price_minor"))]
    subs = {r.org_id: r for r in conn.execute(text("""SELECT s.*, p.code, p.name AS plan_name, p.max_assets, p.max_users
                                                      FROM novrsoc.org_subscriptions s JOIN novrsoc.billing_plans p ON p.id = s.plan_id"""))}
    rows = []
    for a in conn.execute(text("SELECT * FROM novrsoc.platform_analytics()")):
        if a.kind != "client":
            continue
        s = subs.get(a.org_id)
        over = []
        if s and s.max_assets and a.assets > s.max_assets:
            over.append(f"assets {a.assets}/{s.max_assets}")
        if s and s.max_users and a.users > s.max_users:
            over.append(f"users {a.users}/{s.max_users}")
        rows.append(OrgBillingRow(org_id=a.org_id, org_name=a.org_name, plan_code=s.code if s else None, plan_name=s.plan_name if s else None,
                                  status=s.status if s else None, renews_at=s.renews_at if s else None, assets=a.assets, users=a.users,
                                  max_assets=s.max_assets if s else None, max_users=s.max_users if s else None, over_limit=over))
    return BillingOverview(plans=plans, organizations=rows,
                           note="No payment provider is configured. Subscriptions are administrative records: NovrSOC takes no payments "
                                "and issues no invoices.")


@router.post("/billing/plans", response_model=BillingPlanView, status_code=201, summary="Create a billing plan")
def create_plan(body: BillingPlanCreate, request: Request, p: Principal = Depends(require("billing:manage")),
                conn: Connection = Depends(request_connection)) -> BillingPlanView:
    try:
        with conn.begin_nested():
            r = conn.execute(text("""INSERT INTO novrsoc.billing_plans (code, name, description, price_minor, currency, billing_interval,
                                                                        max_assets, max_users, features)
                                     VALUES (:c, :n, :d, :pm, :cu, :bi, :ma, :mu, :f) RETURNING *"""),
                             {"c": body.code, "n": body.name, "d": body.description, "pm": body.price_minor, "cu": body.currency,
                              "bi": body.billing_interval, "ma": body.max_assets, "mu": body.max_users, "f": body.features}).one()
    except IntegrityError:
        raise ApiError(409, "conflict", "A plan with this code already exists")
    _audit(p, request, "BILLING_PLAN_CREATED", "billing_plan", body.code)
    return _plan(r)


@router.patch("/billing/plans/{plan_id}", response_model=BillingPlanView, summary="Activate or retire a plan")
def update_plan(plan_id: uuid.UUID, body: BillingPlanUpdate, request: Request, p: Principal = Depends(require("billing:manage")),
                conn: Connection = Depends(request_connection)) -> BillingPlanView:
    r = conn.execute(text("UPDATE novrsoc.billing_plans SET active = :a WHERE id = :i RETURNING *"), {"a": body.active, "i": plan_id}).first()
    if r is None:
        raise not_found("Plan not found")
    _audit(p, request, "BILLING_PLAN_UPDATED", "billing_plan", r.code, {"active": body.active})
    return _plan(r)


@router.put("/billing/subscriptions", response_model=BillingOverview, summary="Set an organization's plan and subscription status")
def set_subscription(body: SubscriptionSet, request: Request, p: Principal = Depends(require("billing:manage")),
                     conn: Connection = Depends(request_connection)) -> BillingOverview:
    kind = conn.execute(text("SELECT kind FROM novrsoc.organizations WHERE id = :o"), {"o": body.org_id}).scalar()
    if kind != "client":
        raise not_found("Client organization not found")
    plan = conn.execute(text("SELECT active, code FROM novrsoc.billing_plans WHERE id = :i"), {"i": body.plan_id}).first()
    if plan is None or not plan.active:
        raise ApiError(422, "validation_error", "The plan does not exist or is retired")
    conn.execute(text("""INSERT INTO novrsoc.org_subscriptions (org_id, plan_id, status, renews_at, notes, updated_by)
                         VALUES (:o, :p, :s, :r, :n, :u)
                         ON CONFLICT (org_id) DO UPDATE SET plan_id = EXCLUDED.plan_id, status = EXCLUDED.status, renews_at = EXCLUDED.renews_at,
                           notes = EXCLUDED.notes, updated_by = EXCLUDED.updated_by, updated_at = now()"""),
                 {"o": body.org_id, "p": body.plan_id, "s": body.status, "r": body.renews_at, "n": body.notes, "u": p.user_id})
    _audit(p, request, "SUBSCRIPTION_SET", "organization", str(body.org_id), {"plan": plan.code, "status": body.status})
    return billing(p, conn)


# ---------------------------------------------------------------- authorized data exports (active organization)
_DATASETS = {
    "alerts": ("observed_at", """SELECT id, observed_at, severity, status, rule_id, rule_description, agent_id, agent_name, host(src_ip) AS src_ip,
                                        source FROM novrsoc.alerts WHERE observed_at >= :s AND observed_at < :e ORDER BY observed_at"""),
    "cases": ("created_at", """SELECT id, 'CASE-' || lpad(number::text, 6, '0') AS reference, title, severity, status, source, created_at, closed_at,
                                      sla_response_due_at, sla_resolution_due_at, resolved_at FROM novrsoc.cases
                               WHERE created_at >= :s AND created_at < :e ORDER BY created_at"""),
    "vms_findings": ("first_seen_at", """SELECT id, host, port, protocol, title, severity, cvss, array_to_string(cves, ' ') AS cves, status, priority,
                                                risk_score, first_seen_at, last_seen_at FROM novrsoc.vms_findings
                                         WHERE last_seen_at >= :s AND first_seen_at < :e ORDER BY first_seen_at"""),
    "assets": ("last_seen_at", """SELECT id, kind, display_name, hostname, fqdn, host(primary_ip) AS primary_ip, classification, criticality,
                                         exposure, owner, status, first_seen_at, last_seen_at FROM novrsoc.assets
                                  WHERE last_seen_at >= :s AND first_seen_at < :e ORDER BY display_name"""),
    "audit_events": ("occurred_at", """SELECT id, occurred_at, actor_type, actor_label, action, outcome, resource_type, resource_id
                                       FROM novrsoc.audit_events WHERE occurred_at >= :s AND occurred_at < :e ORDER BY id"""),
    "ti_indicators": ("imported_at", """SELECT id, type, value, tlp, confidence, source, valid_from, valid_until, imported_at
                                        FROM novrsoc.ti_indicators WHERE imported_at >= :s AND imported_at < :e ORDER BY imported_at"""),
}


def _export_view(r) -> DataExportView:
    state = "revoked" if r.revoked_at else "expired" if r.expires_at <= _NOW() else "available"
    return DataExportView(id=r.id, dataset=r.dataset, format=r.format, period_start=r.period_start, period_end=r.period_end,
                          justification=r.justification, recipient=r.recipient, row_count=r.row_count, truncated=r.truncated, sha256=r.sha256,
                          requested_by=_ActorRef(type="user", id=r.requested_by, label=r.requested_label), created_at=r.created_at,
                          expires_at=r.expires_at, downloads=r.downloads, state=state)


_EXPORT_COLS = ("id, dataset, format, period_start, period_end, justification, recipient, row_count, truncated, sha256, requested_by, "
                "requested_label, created_at, expires_at, downloads, revoked_at")


@router.get("/exports", response_model=DataExportList, summary="Authorized data exports of the active organization")
def list_exports(p: Principal = Depends(require("exports:manage")), conn: Connection = Depends(request_connection)) -> DataExportList:
    rows = conn.execute(text(f"SELECT {_EXPORT_COLS} FROM novrsoc.data_exports ORDER BY created_at DESC LIMIT 200")).all()
    return DataExportList(items=[_export_view(r) for r in rows], max_rows=EXPORT_MAX_ROWS)


@router.post("/exports", response_model=DataExportView, status_code=201, summary="Create an authorized export (justification and recipient required)")
def create_export(body: DataExportCreate, request: Request, p: Principal = Depends(require("exports:manage")),
                  conn: Connection = Depends(request_connection)) -> DataExportView:
    if body.dataset == "audit_events" and not p.has("audit:read"):
        raise ApiError(403, "forbidden", "Exporting audit events needs audit:read", {"required": "audit:read"})
    _, sql = _DATASETS[body.dataset]
    rows = conn.execute(text(sql + f" LIMIT {EXPORT_MAX_ROWS + 1}"), {"s": body.period_start, "e": body.period_end}).mappings().all()
    truncated = len(rows) > EXPORT_MAX_ROWS
    rows = rows[:EXPORT_MAX_ROWS]
    if body.format == "json":
        content = _json.dumps({"dataset": body.dataset, "period_start": body.period_start.isoformat(), "period_end": body.period_end.isoformat(),
                               "rows": [dict(r) for r in rows]}, default=str, sort_keys=True)
    else:
        buf = _io.StringIO()
        w = _csv.writer(buf)
        cols = list(rows[0].keys()) if rows else []
        w.writerow(cols)
        for r in rows:
            w.writerow(["" if r[c] is None else str(r[c]) for c in cols])
        content = buf.getvalue()
    digest = _hashlib.sha256(content.encode()).hexdigest()
    r = conn.execute(text(f"""INSERT INTO novrsoc.data_exports (org_id, dataset, format, period_start, period_end, justification, recipient,
                                                                row_count, truncated, content, sha256, requested_by, requested_label, expires_at)
                              VALUES (:o, :d, :f, :s, :e, :j, :rc, :n, :t, :c, :h, :u, :l, :x) RETURNING {_EXPORT_COLS}"""),
                     {"o": p.org_id, "d": body.dataset, "f": body.format, "s": body.period_start, "e": body.period_end, "j": body.justification,
                      "rc": body.recipient, "n": len(rows), "t": truncated, "c": content, "h": digest, "u": p.user_id, "l": p.email,
                      "x": _NOW() + _td(days=body.expires_in_days)}).one()
    _audit(p, request, "DATA_EXPORT_CREATED", "data_export", str(r.id), {"dataset": body.dataset, "rows": len(rows), "recipient": body.recipient,
                                                                        "sha256": digest})
    return _export_view(r)


@router.get("/exports/{export_id}/download", summary="Download an export (audited; refused once expired or revoked)",
            responses={200: {"content": {"text/csv": {}, "application/json": {}}}})
def download_export(export_id: uuid.UUID, request: Request, p: Principal = Depends(require("exports:manage")),
                    conn: Connection = Depends(request_connection)) -> _Response:
    r = conn.execute(text("SELECT * FROM novrsoc.data_exports WHERE id = :i FOR UPDATE"), {"i": export_id}).first()
    if r is None:
        raise not_found("Export not found")
    if r.revoked_at or r.expires_at <= _NOW():
        audit.record("DATA_EXPORT_DOWNLOAD_REFUSED", "denied", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="data_export",
                     resource_id=str(export_id), request_id=request.state.request_id, ip=client_ip(request))
        raise ApiError(410, "export_unavailable", "This export has expired or was revoked")
    if _hashlib.sha256(r.content.encode()).hexdigest() != r.sha256:
        raise ApiError(409, "integrity_check_failed", "The stored export does not match its checksum")
    conn.execute(text("UPDATE novrsoc.data_exports SET downloads = downloads + 1 WHERE id = :i"), {"i": export_id})
    _audit(p, request, "DATA_EXPORT_DOWNLOADED", "data_export", str(export_id), {"dataset": r.dataset})
    return _Response(r.content, media_type="application/json" if r.format == "json" else "text/csv",
                     headers={"Content-Disposition": f'attachment; filename="novrsoc-{r.dataset}-{r.created_at:%Y%m%d-%H%M%S}.{r.format}"',
                              "X-Content-SHA256": r.sha256})


@router.post("/exports/{export_id}/revoke", response_model=DataExportView, summary="Revoke an export (it can no longer be downloaded)")
def revoke_export(export_id: uuid.UUID, request: Request, p: Principal = Depends(require("exports:manage")),
                  conn: Connection = Depends(request_connection)) -> DataExportView:
    r = conn.execute(text(f"UPDATE novrsoc.data_exports SET revoked_at = now() WHERE id = :i AND revoked_at IS NULL RETURNING {_EXPORT_COLS}"),
                     {"i": export_id}).first()
    if r is None:
        raise not_found("Active export not found")
    _audit(p, request, "DATA_EXPORT_REVOKED", "data_export", str(export_id))
    return _export_view(r)


# ---------------------------------------------------------------- teams and memberships (analyst onboarding)
def _team(conn: Connection, r) -> TeamView:
    members = conn.execute(text("""SELECT tm.user_id, u.email::text AS email, m.role_key, tm.team_role FROM novrsoc.team_members tm
                                   JOIN novrsoc.users u ON u.id = tm.user_id LEFT JOIN novrsoc.memberships m ON m.user_id = tm.user_id AND m.org_id = tm.org_id
                                   WHERE tm.team_id = :t ORDER BY tm.team_role, u.email"""), {"t": r.id}).all()
    return TeamView(id=r.id, name=r.name, description=r.description, created_at=r.created_at,
                    members=[TeamMemberView(user_id=m.user_id, email=m.email, role=m.role_key or "", team_role=m.team_role) for m in members])


@router.get("/teams", response_model=TeamList, summary="Analyst teams of the active organization")
def list_teams(p: Principal = Depends(require("users:manage")), conn: Connection = Depends(request_connection)) -> TeamList:
    return TeamList(items=[_team(conn, r) for r in conn.execute(text("SELECT * FROM novrsoc.teams ORDER BY name"))])


@router.post("/teams", response_model=TeamView, status_code=201, summary="Create a team")
def create_team(body: TeamCreate, request: Request, p: Principal = Depends(require("users:manage")),
                conn: Connection = Depends(request_connection)) -> TeamView:
    try:
        with conn.begin_nested():
            r = conn.execute(text("INSERT INTO novrsoc.teams (org_id, name, description) VALUES (:o, :n, :d) RETURNING *"),
                             {"o": p.org_id, "n": body.name, "d": body.description}).one()
    except IntegrityError:
        raise ApiError(409, "conflict", "A team with this name already exists")
    _audit(p, request, "TEAM_CREATED", "team", str(r.id), {"name": body.name})
    return _team(conn, r)


@router.post("/teams/{team_id}/members", response_model=TeamView, summary="Add a member of the organization to a team")
def add_member(team_id: uuid.UUID, body: TeamMemberAdd, request: Request, p: Principal = Depends(require("users:manage")),
               conn: Connection = Depends(request_connection)) -> TeamView:
    r = conn.execute(text("SELECT * FROM novrsoc.teams WHERE id = :i"), {"i": team_id}).first()
    if r is None:
        raise not_found("Team not found")
    if conn.execute(text("SELECT 1 FROM novrsoc.memberships WHERE org_id = :o AND user_id = :u"), {"o": p.org_id, "u": body.user_id}).first() is None:
        raise ApiError(422, "validation_error", "The user is not a member of this organization")
    conn.execute(text("""INSERT INTO novrsoc.team_members (team_id, org_id, user_id, team_role) VALUES (:t, :o, :u, :r)
                         ON CONFLICT (team_id, user_id) DO NOTHING"""), {"t": team_id, "o": p.org_id, "u": body.user_id, "r": body.team_role})
    _audit(p, request, "TEAM_MEMBER_ADDED", "team", str(team_id), {"user": str(body.user_id), "team_role": body.team_role})
    return _team(conn, r)


@router.delete("/teams/{team_id}/members/{user_id}", response_model=TeamView, summary="Remove a member from a team")
def remove_member(team_id: uuid.UUID, user_id: uuid.UUID, request: Request, p: Principal = Depends(require("users:manage")),
                  conn: Connection = Depends(request_connection)) -> TeamView:
    r = conn.execute(text("SELECT * FROM novrsoc.teams WHERE id = :i"), {"i": team_id}).first()
    if r is None or conn.execute(text("DELETE FROM novrsoc.team_members WHERE team_id = :t AND user_id = :u RETURNING user_id"),
                                 {"t": team_id, "u": user_id}).first() is None:
        raise not_found("Team member not found")
    _audit(p, request, "TEAM_MEMBER_REMOVED", "team", str(team_id), {"user": str(user_id)})
    return _team(conn, r)


def _memberships(conn: Connection, user_id: uuid.UUID) -> MembershipList:
    rows = conn.execute(text("""SELECT m.org_id, o.name, m.role_key, m.access_scope FROM novrsoc.memberships m
                                JOIN novrsoc.organizations o ON o.id = m.org_id WHERE m.user_id = :u ORDER BY m.access_scope, o.name"""),
                        {"u": user_id}).all()
    return MembershipList(user_id=user_id, items=[MembershipView(org_id=r.org_id, org_name=r.name, role=r.role_key, access_scope=r.access_scope)
                                                  for r in rows])


@router.get("/users/{user_id}/memberships", response_model=MembershipList, summary="A user's organizations (home and assignments)")
def list_memberships(user_id: uuid.UUID, p: Principal = Depends(require("users:manage")),
                     conn: Connection = Depends(request_connection)) -> MembershipList:
    if conn.execute(text("SELECT 1 FROM novrsoc.users WHERE id = :u"), {"u": user_id}).first() is None:
        raise not_found("User not found")
    return _memberships(conn, user_id)


@router.post("/users/{user_id}/memberships", response_model=MembershipList, summary="Assign a user to another organization (analyst onboarding)")
def grant_membership(user_id: uuid.UUID, body: MembershipGrant, request: Request, p: Principal = Depends(require("users:manage")),
                     conn: Connection = Depends(request_connection)) -> MembershipList:
    home = conn.execute(text("SELECT role_key, org_id FROM novrsoc.memberships WHERE user_id = :u AND access_scope = 'home'"), {"u": user_id}).first()
    if home is None:
        raise not_found("User not found")
    if home.role_key in ("portal_user", "super_admin"):
        raise ApiError(422, "validation_error", f"A {home.role_key} account cannot be assigned to other organizations")
    if body.access_scope == "operations" and home.role_key == "executive":
        raise ApiError(422, "validation_error", "Executives receive reporting assignments only")
    if conn.execute(text("SELECT kind FROM novrsoc.organizations WHERE id = :o"), {"o": body.org_id}).scalar() != "client":
        raise not_found("Client organization not found")
    try:
        with conn.begin_nested():
            conn.execute(text("""INSERT INTO novrsoc.memberships (user_id, org_id, role_key, access_scope) VALUES (:u, :o, :r, :s)"""),
                         {"u": user_id, "o": body.org_id, "r": home.role_key, "s": body.access_scope})
    except IntegrityError:
        raise ApiError(409, "conflict", "The user already has access to this organization")
    _audit(p, request, "MEMBERSHIP_GRANTED", "user", str(user_id), {"org": str(body.org_id), "scope": body.access_scope})
    return _memberships(conn, user_id)


@router.delete("/users/{user_id}/memberships/{org_id}", response_model=MembershipList, summary="Remove an assignment (never the home membership)")
def revoke_membership(user_id: uuid.UUID, org_id: uuid.UUID, request: Request, p: Principal = Depends(require("users:manage")),
                      conn: Connection = Depends(request_connection)) -> MembershipList:
    r = conn.execute(text("""DELETE FROM novrsoc.memberships WHERE user_id = :u AND org_id = :o AND access_scope <> 'home' RETURNING id"""),
                     {"u": user_id, "o": org_id}).first()
    if r is None:
        raise not_found("Assignment not found")
    _audit(p, request, "MEMBERSHIP_REVOKED", "user", str(user_id), {"org": str(org_id)})
    return _memberships(conn, user_id)


@router.get("/onboarding", response_model=OnboardingStatus, summary="Onboarding progress of the active organization")
def onboarding(p: Principal = Depends(require("users:manage")), conn: Connection = Depends(request_connection)) -> OnboardingStatus:
    org = conn.execute(text("SELECT id, slug FROM novrsoc.organizations WHERE id = :o"), {"o": p.org_id}).one()
    q = lambda sql: bool(conn.execute(text(sql), {"o": p.org_id}).scalar())  # noqa: E731
    steps = {
        "organization_created": True,
        "users_added": q("SELECT count(*) > 0 FROM novrsoc.memberships WHERE org_id = :o"),
        "wazuh_groups_mapped": q("SELECT count(*) > 0 FROM novrsoc.wazuh_group_mappings"),
        "sites_defined": q("SELECT count(*) > 0 FROM novrsoc.sites"),
        "sla_policies_set": q("SELECT count(*) > 0 FROM novrsoc.sla_policies"),
        "response_policy_set": q("SELECT count(*) > 0 FROM novrsoc.soar_policies"),
        "subscription_set": q("SELECT count(*) > 0 FROM novrsoc.org_subscriptions WHERE org_id = :o"),
        "assets_inventoried": q("SELECT count(*) > 0 FROM novrsoc.assets"),
    }
    return OnboardingStatus(org_id=org.id, org_slug=str(org.slug), steps=steps, next_step=next((k for k, v in steps.items() if not v), None))


# ---------------------------------------------------------------- platform analytics and health
@router.get("/analytics", response_model=PlatformAnalytics, summary="Platform analytics across organizations (counts only)")
def analytics(p: Principal = Depends(require("platform:monitor")), conn: Connection = Depends(request_connection)) -> PlatformAnalytics:
    rows = [OrgAnalyticsRow(**dict(r._mapping)) for r in conn.execute(text("SELECT * FROM novrsoc.platform_analytics()"))]
    totals = {k: sum(getattr(r, k) for r in rows) for k in ("users", "assets", "alerts_7d", "open_alerts", "open_cases", "open_findings",
                                                            "critical_findings")}
    totals["organizations"] = len(rows)
    return PlatformAnalytics(generated_at=_NOW(), organizations=rows, totals=totals)


_CONNECTOR = {"connected": "ok", "local_fixture": "degraded", "unconfigured": "unconfigured", "unavailable": "failing", "error": "failing"}


@router.get("/health", response_model=PlatformHealth, summary="Platform health: measured component states, queues, workers and failures")
def health(p: Principal = Depends(require("platform:monitor")), conn: Connection = Depends(request_connection),
           settings: _Settings = Depends(_get_settings)) -> PlatformHealth:
    from app.main import expected_migration_head
    from app.routers.platform import _nhai
    h = conn.execute(text("SELECT novrsoc.platform_health()")).scalar()
    now = _NOW()
    c: list[ComponentHealth] = []
    db = h["database"]
    c.append(ComponentHealth(key="database", label="PostgreSQL", state="ok", checked_at=now,
                             detail=f"PostgreSQL {db['server_version']}, {round(db['size_bytes'] / 1048576, 1)} MiB, {db['connections']} connections"))
    rev = conn.execute(text("SELECT version_num FROM novrsoc.alembic_version")).scalar()
    head = expected_migration_head()
    c.append(ComponentHealth(key="migrations", label="Schema migrations", state="ok" if rev == head else "failing", checked_at=now,
                             detail=f"at {rev}, build expects {head}"))
    for st in _registry.wazuh_states(settings):
        c.append(ComponentHealth(key=st.connector, label=st.connector.replace("_", " ").title(), state=_CONNECTOR[st.state],
                                 detail=st.detail or st.state, checked_at=st.checked_at))
    nhai_mod, ollama = _nhai(conn, settings)
    c.append(ComponentHealth(key="nhai", label="NHAI inference", state=_CONNECTOR[ollama.state], detail=nhai_mod.note, checked_at=ollama.checked_at))
    c.append(ComponentHealth(key="soar_bridge", label="SOAR execution bridge (Server 1)", checked_at=now,
                             state="unconfigured" if not settings.soar_bridge_url else "unknown",
                             detail="Not configured: consequential steps fail closed." if not settings.soar_bridge_url else
                             "Configured; its state is established by each dispatch receipt (see SOAR failures below)."))
    workers = h["vms_workers"]
    stale = [w for w in workers if _dt.fromisoformat(w["received_at"]) < now - _td(seconds=180)]
    c.append(ComponentHealth(key="vms_workers", label="VMS workers (Server 2, vms profile)",
                             state="unconfigured" if not workers else "degraded" if stale else "ok",
                             detail=f"{len(workers)} worker(s), {len(stale)} stale" if workers else "No VMS worker has reported."))
    last = h["ingest"]["last_batch_at"]
    c.append(ComponentHealth(key="forwarder", label="Alert forwarder (Server 1)",
                             state="unconfigured" if last is None else "ok" if _dt.fromisoformat(last) > now - _td(hours=1) else "degraded",
                             detail="No alert batch received yet." if last is None else f"Last batch {last}; {h['ingest']['batches_24h']} in 24 h; "
                                                                                       f"{h['ingest']['quarantined_24h']} quarantined"))
    q = h["nhai_queue"]
    oldest = q["oldest_queued_at"]
    c.append(ComponentHealth(key="nhai_queue", label="NHAI job queue",
                             state="degraded" if oldest and _dt.fromisoformat(oldest) < now - _td(minutes=30) else "ok",
                             detail=f"{q['queued']} queued, {q['running']} running, {q['failed_24h']} failed in 24 h"))
    b = h["backups"]
    c.append(ComponentHealth(key="backups", label="Encrypted database backups",
                             state="unconfigured" if b["last_succeeded_at"] is None else
                             "ok" if _dt.fromisoformat(b["last_succeeded_at"]) > now - _td(hours=26) else "degraded",
                             detail="No backup recorded." if b["last_succeeded_at"] is None else
                             f"Last success {b['last_succeeded_at']}; last drill {b['last_drill_status'] or 'none'}"))
    for hb in conn.execute(text("SELECT * FROM novrsoc.platform_heartbeats ORDER BY component")):
        fresh = hb.last_seen_at > now - _td(minutes=10)
        c.append(ComponentHealth(key=hb.component, label=hb.component.replace("_", " ").title(), checked_at=hb.last_seen_at,
                                 state=hb.state if fresh else "failing", detail=hb.detail if fresh else f"No heartbeat since {hb.last_seen_at}"))
    if not any(x.key == "jobs_worker" for x in c):
        c.append(ComponentHealth(key="jobs_worker", label="Background jobs worker", state="unknown", detail="The jobs worker has not reported."))
    return PlatformHealth(generated_at=now, components=c, workers=workers, failures_24h=h["failures_24h"],
                          queues={"nhai": q, "soar": h["soar"], "vms": h["vms_jobs"], "ingest": h["ingest"]})


@router.get("/wazuh/quarantine", response_model=QuarantineSummary, summary="Alerts quarantined because no organization maps their groups")
def quarantine(p: Principal = Depends(require("users:manage")), conn: Connection = Depends(request_connection)) -> QuarantineSummary:
    n = conn.execute(text("SELECT count(*) FROM novrsoc.alert_quarantine WHERE received_at > now() - interval '24 hours'")).scalar()
    by = {r[0]: r[1] for r in conn.execute(text("SELECT reason, count(*) FROM novrsoc.alert_quarantine GROUP BY reason"))}
    groups = [r[0] for r in conn.execute(text("""SELECT DISTINCT g FROM novrsoc.alert_quarantine q, unnest(q.agent_groups) g
                                                 WHERE q.reason = 'no_organization_for_groups' ORDER BY g LIMIT 100"""))]
    return QuarantineSummary(last_24h=n, by_reason=by, unmapped_groups=groups)
