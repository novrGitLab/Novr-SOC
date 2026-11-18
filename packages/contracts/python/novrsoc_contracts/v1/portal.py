"""Organization portals, branding, invitations and guided onboarding (additive, v1).

One shared deployment serves the platform host and every organization portal (<subdomain>.<base domain>). The host only
selects which organization's branding a page shows and restricts who may sign in there; it never grants access.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from .common import Contract

HexColor = Annotated[str, Field(pattern=r"^#[0-9a-fA-F]{6}$")]
Subdomain = Annotated[str, Field(pattern=r"^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$")]
InviteRole = Literal["soc_manager", "analyst", "executive", "portal_user"]
AgentOs = Literal["windows", "linux", "macos"]


# ---------------------------------------------------------------- public: what a portal page may know before sign-in
class PortalTheme(Contract):
    """An APPROVED theme: derived from the organization's primary color only when it reaches WCAG AA against white."""
    primary: str
    primary_hover: str
    primary_fill: str
    tint_light: str
    tint_dark: str
    on_primary: str


class PortalBranding(Contract):
    display_name: str
    primary_color: str | None = None
    secondary_color: str | None = None
    text_on_primary: str = "#ffffff"
    logo_url: str | None = Field(default=None, description="Relative URL of the logo, versioned by its digest")
    theme: PortalTheme | None = Field(default=None, description="Applied throughout the portal; null when the colors are not approved")


class PortalOrg(Contract):
    slug: str
    name: str


class PortalInfo(Contract):
    kind: Literal["platform", "tenant"]
    organization: PortalOrg | None = None
    branding: PortalBranding | None = None


# ---------------------------------------------------------------- platform administration: portal and branding
class OrgPortalUpdate(Contract):
    portal_subdomain: Subdomain | None = None
    portal_enabled: bool = False
    display_name: Annotated[str, Field(max_length=120)] = ""
    primary_color: HexColor | None = None
    secondary_color: HexColor | None = None


class OrgPortalView(Contract):
    portal_subdomain: str | None = None
    portal_enabled: bool
    url: str | None = Field(default=None, description="The portal address, when enabled and the installation has a base domain")
    display_name: str
    primary_color: str | None = None
    secondary_color: str | None = None
    text_on_primary: str | None = None
    contrast_primary_on_white: float | None = None
    has_logo: bool
    logo_sha256: str | None = None
    theme_applied: bool = Field(default=False, description="True when the primary color passes the contrast check and themes the portal")
    warnings: list[str] = []


class LogoUpload(Contract):
    content_type: Literal["image/png", "image/jpeg", "image/webp", "image/svg+xml"]
    data_base64: Annotated[str, Field(min_length=4, max_length=360_000)]


# ---------------------------------------------------------------- invitations
class InvitationCreate(Contract):
    email: Annotated[str, Field(max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
    role: InviteRole = "soc_manager"


class InvitationView(Contract):
    id: uuid.UUID
    email: str
    role: InviteRole
    state: Literal["open", "accepted", "revoked", "expired"]
    invited_label: str
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None = None


class InvitationCreated(Contract):
    invitation: InvitationView
    link: str = Field(description="Shown ONCE: only its SHA-256 is stored. The token is in the URL fragment, never sent to a server log")


class InvitationList(Contract):
    items: list[InvitationView]


class InvitationToken(Contract):
    token: Annotated[str, Field(min_length=20, max_length=200)]


class InvitationPreview(Contract):
    state: Literal["open", "accepted", "revoked", "expired", "organization_inactive"]
    email: str | None = None
    role: InviteRole | None = None
    organization: str | None = None
    expires_at: datetime | None = None


class InvitationAccept(Contract):
    token: Annotated[str, Field(min_length=20, max_length=200)]
    display_name: Annotated[str, Field(min_length=1, max_length=200)]
    password: Annotated[str, Field(min_length=12, max_length=1024)]


class InvitationAccepted(Contract):
    email: str
    sign_in_url: str


# ---------------------------------------------------------------- agent group and guided onboarding
class AgentGroupView(Contract):
    provisioned: bool
    group_name: str | None = Field(default=None, description="Shown only to the organization and NovrSOC administrators")
    created_at: datetime | None = None
    on_manager: bool | None = Field(default=None, description="Whether the group exists on the NovrSIEM manager (null: not checked)")
    manager_detail: str = ""


class InstallerRequest(Contract):
    os: AgentOs
    endpoints: Annotated[int, Field(ge=1, le=500, description="How many endpoints this command may enroll")] = 10


class InstallerCommand(Contract):
    os: AgentOs
    command: str = Field(description="Downloads the organization's NovrAgent installer and runs it; carries no password")
    ticket_id: uuid.UUID
    max_endpoints: int
    expires_at: datetime
    run_as: str
    agent_version: str
    notes: list[str] = []


class AgentEnrollmentTicket(Contract):
    id: uuid.UUID
    os: AgentOs
    max_uses: int
    uses: int
    state: Literal["open", "used_up", "expired", "revoked"]
    created_label: str
    created_at: datetime
    expires_at: datetime


class AgentEnrollmentTicketList(Contract):
    items: list[AgentEnrollmentTicket]


class AgentEnrollmentRequest(Contract):
    """Sent by the installer running on the endpoint (public; the ticket is the only key)."""
    ticket: Annotated[str, Field(min_length=30, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")]
    hostname: Annotated[str, Field(min_length=1, max_length=64)]
    os: AgentOs


class AgentEnrollmentResult(Contract):
    agent_id: str
    name: str
    key: str = Field(description="The agent's key, imported by the installer; returned once over TLS and never stored by NovrSOC")


class AgentEnrollmentStatus(Contract):
    available: bool
    detail: str = ""
    manager_version: str | None = None
    agent_version: str | None = None
    enrolled_agents: int = 0
    open_tickets: int = 0


class AssetSyncStatus(Contract):
    interval_minutes: int = Field(description="0: scheduled sync is off (on demand only)")
    last_run_at: datetime | None = None
    last_outcome: str | None = None
    last_detail: str = ""
    next_due_at: datetime | None = None


class OnboardingAgents(Contract):
    state: str = Field(description="The agent data source state: connected, local_fixture, unconfigured, unavailable, error")
    total: int = 0
    active: int = 0
    disconnected: int = 0
    never_connected: int = 0
    pending: int = 0


class OnboardingTelemetry(Contract):
    alerts_24h: int = 0
    last_alert_at: datetime | None = None
    assets: int = 0
    vms_enrolled: int = 0


class OnboardingSources(Contract):
    total: int = 0
    pending_verification: int = 0
    receiving: int = 0
    never_received: int = 0


class OnboardingStep(Contract):
    key: str
    label: str
    done: bool
    detail: str = ""


class SyslogTarget(Contract):
    address: str | None = None
    port: int
    protocols: list[str]


class TenantOnboarding(Contract):
    organization: PortalOrg
    portal_url: str | None = None
    agent_group: AgentGroupView
    installer_available: bool
    installer_reason: str = ""
    enrollment: AgentEnrollmentStatus | None = None
    asset_sync: AssetSyncStatus | None = None
    agents: OnboardingAgents
    telemetry: OnboardingTelemetry
    sources: OnboardingSources
    syslog: SyslogTarget
    steps: list[OnboardingStep]
    completed: int
    total: int
