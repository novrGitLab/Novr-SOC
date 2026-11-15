"""Foundation HTTP API contracts (implemented by apps/api in Phase 2): health, auth, organisations,
sites, audit events, service identity, CNII access check."""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, field_validator

from .common import Contract, ShortText

Role = Literal["super_admin", "soc_manager", "analyst", "executive", "portal_user"]
AccessScope = Literal["home", "operations", "reporting"]


class HealthResponse(Contract):
    status: Literal["ok"]
    service: str
    version: str


class ReadinessCheck(Contract):
    name: str
    ok: bool
    detail: str = ""


class ReadinessResponse(Contract):
    status: Literal["ready", "not_ready"]
    checks: list[ReadinessCheck]


class LoginRequest(Contract):
    email: Annotated[str, Field(min_length=3, max_length=254)]
    password: Annotated[str, Field(min_length=1, max_length=1024)]


class OrgSummary(Contract):
    id: uuid.UUID
    slug: str
    name: str


class MembershipSummary(Contract):
    org: OrgSummary
    role: Role
    access_scope: AccessScope


class UserSummary(Contract):
    id: uuid.UUID
    email: str
    display_name: str


class SessionInfo(Contract):
    """GET /api/v1/auth/me. Permissions are those of the home role, applied to the active organisation."""
    user: UserSummary
    role: Role
    home_org: OrgSummary
    active_org: OrgSummary
    cross_org: bool
    permissions: list[str]
    memberships: list[MembershipSummary]
    password_change_required: bool = Field(False, description="The account still has a temporary password: every "
                                           "route except /auth/me, /auth/password and /auth/logout answers 403 "
                                           "password_change_required until it is changed")


class PasswordChangeRequest(Contract):
    """POST /api/v1/auth/password. The new password must differ from the current one; other sessions are revoked."""
    current_password: Annotated[str, Field(min_length=1, max_length=1024)]
    new_password: Annotated[str, Field(min_length=12, max_length=1024)]


class LoginResponse(Contract):
    session: SessionInfo
    csrf_token: str = Field(description="Send back as X-CSRF-Token on POST/PUT/PATCH/DELETE (also set as a cookie)")


class OrgList(Contract):
    items: list[OrgSummary]
    all_organizations: bool = Field(description="True for super_admin: the list is every active organisation")


class SiteCreate(Contract):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    description: Annotated[str, Field(max_length=2000)] = ""
    network_cidrs: Annotated[list[str], Field(max_length=64)] = []

    @field_validator("network_cidrs")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(c, strict=False)) for c in v]


class Site(Contract):
    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    description: str
    network_cidrs: list[str]
    created_at: datetime


class SiteList(Contract):
    items: list[Site]


class AuditEvent(Contract):
    id: int
    occurred_at: datetime
    org_id: uuid.UUID | None
    actor_type: Literal["user", "service", "system"]
    actor_id: uuid.UUID | None
    actor_label: str
    action: str
    outcome: Literal["success", "denied", "failure"]
    resource_type: str
    resource_id: str
    request_id: str
    details: dict = Field(default={}, description="Consolidation: the event's recorded details (never secrets)")


class AuditEventList(Contract):
    items: list[AuditEvent]
    total: int | None = None


class ServiceWhoAmI(Contract):
    """GET /api/v1/service/whoami. Everything here comes from the identity record, nothing from the request."""
    identity_id: uuid.UUID
    org_id: uuid.UUID
    site_id: uuid.UUID | None
    kind: Literal["collector", "vms_worker", "forwarder", "email_gateway", "backup_agent"]
    scopes: list[str]


class CniiAccessResponse(Contract):
    sector: ShortText
    designation_id: uuid.UUID
    active_org_id: uuid.UUID
    note: str = "Access check only. CNII data endpoints are not built in Phase 2."


class ModuleState(Contract):
    """Phase 4: what a product module can do right now, as the API knows it."""
    key: Annotated[str, Field(pattern=r"^[a-z_]{2,40}$")]
    label: ShortText
    state: Literal["live", "not_available", "restricted"]
    note: ShortText = ""


class PlatformStatus(Contract):
    """Phase 4 dashboard readiness. Connector states come from configuration and real checks only."""
    database: Literal["ok", "unavailable"]
    migration: ShortText
    connectors: list["ConnectorState"]
    modules: list[ModuleState]


from .endpoints import ConnectorState  # noqa: E402  (shared state model; defined with the endpoint contracts)

PlatformStatus.model_rebuild()


# ---------------------------------------------------------------- Phase 6 pilot (additive): administration
RoleName = Literal["super_admin", "soc_manager", "analyst", "executive", "portal_user"]
ServiceKind = Literal["collector", "vms_worker", "forwarder", "email_gateway", "backup_agent", "ti_feeder"]


class AdminOrg(Contract):
    id: uuid.UUID
    slug: str
    name: str
    kind: Literal["platform", "client"]
    status: Literal["active", "suspended"]
    created_at: datetime


class AdminOrgCreate(Contract):
    slug: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
    name: Annotated[str, Field(min_length=1, max_length=200)]


class AdminOrgList(Contract):
    items: list[AdminOrg]


class AdminUser(Contract):
    id: uuid.UUID
    email: str
    display_name: str
    status: Literal["active", "disabled"]
    role: RoleName
    access_scope: Literal["home", "operations", "reporting"]
    locked: bool
    last_login_at: datetime | None = None


class AdminUserList(Contract):
    items: list[AdminUser]


class AdminUserCreate(Contract):
    email: Annotated[str, Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
    display_name: Annotated[str, Field(max_length=200)] = ""
    role: RoleName
    access_scope: Literal["home", "operations", "reporting"] = "home"


class AdminUserCreated(Contract):
    """The temporary password is shown ONCE, here; it is stored only as a hash."""
    user: AdminUser
    temporary_password: str


class UserStatusUpdate(Contract):
    status: Literal["active", "disabled"]


class ServiceIdentityView(Contract):
    id: uuid.UUID
    kind: ServiceKind
    name: str
    scopes: list[str]
    status: Literal["active", "revoked"]
    site_id: uuid.UUID | None = None
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class ServiceIdentityList(Contract):
    items: list[ServiceIdentityView]


class ServiceIdentityCreate(Contract):
    kind: ServiceKind
    name: Annotated[str, Field(min_length=1, max_length=120)]
    scopes: Annotated[list[Annotated[str, Field(pattern=r"^[a-z_]+:[a-z_]+$")]], Field(max_length=10)] = []
    site_id: uuid.UUID | None = None


class ServiceIdentityIssued(Contract):
    """The credential (nsk_...) is shown ONCE, here; only its SHA-256 is stored."""
    identity: ServiceIdentityView
    credential: str


class BackupRunView(Contract):
    id: uuid.UUID
    kind: Literal["logical_dump", "wal_archive"]
    started_at: datetime
    finished_at: datetime | None = None
    status: Literal["running", "succeeded", "failed"]
    target: str
    size_bytes: int | None = None
    sha256: str | None = None
    encrypted: bool
    note: str = ""
    last_drill_status: Literal["succeeded", "failed"] | None = None
    last_drill_at: datetime | None = None


class BackupRunList(Contract):
    items: list[BackupRunView]
