"""Collector contracts v1 (contract only; the multi-tenant collector is built by workstream C).

Identity model:
  * A collector is a service identity bound to exactly ONE organisation and ONE site.
  * It authenticates with its machine credential. NOTHING it sends names an organisation: the API takes
    org_id and site_id from the identity record. A payload field claiming either is rejected
    (extra="forbid"), never trusted.
  * Network identity is (site_id, ip). The same private address at two sites is two different hosts.
  * Credentials rotate with an overlap window, and are revocable immediately.

Flow:
  1. An operator creates an enrollment grant (EnrollmentGrantCreate) -> a one-time enrollment code.
  2. The collector redeems it (EnrollmentRequest) -> EnrollmentResponse with its machine credential.
  3. Heartbeat (CollectorHeartbeat) -> HeartbeatAck, which says whether new configuration exists.
  4. Configuration retrieval (CollectorConfig), versioned and signed by the API.
  5. Telemetry batches (TelemetryBatch) -> TelemetryAck (at-least-once; ack only once durably stored).
  6. Rotation (CredentialRotationRequest/Response) and revocation (CredentialRevocation, operator side).
  7. Approved scan connectivity (ScanConnectivityAssignment) and asset discovery (DiscoveryReport).
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .common import (Contract, IdempotencyKey, Internal, MachineInbound, MachineOutbound, ShortText,
                     SiteScopedAddress)


class Capability(str, Enum):
    SYSLOG_RECEIVE = "syslog_receive"
    WINDOWS_EVENT_FORWARD = "windows_event_forward"
    FILE_TAIL = "file_tail"
    NETWORK_DISCOVERY = "network_discovery"
    SCAN_RELAY = "scan_relay"            # relays APPROVED scan traffic for the VMS worker
    WAZUH_AGENT_BRIDGE = "wazuh_agent_bridge"


# ---------------------------------------------------------------- enrollment (operator -> API)
class EnrollmentGrantCreate(Contract):
    """Operator request (human API, permission service_identities:manage, active org applies)."""
    site_id: uuid.UUID
    name: Annotated[str, Field(min_length=1, max_length=120)]
    capabilities: Annotated[list[Capability], Field(min_length=1)]
    expires_in_minutes: Annotated[int, Field(ge=5, le=24 * 60)] = 60


class EnrollmentGrant(Contract):
    grant_id: uuid.UUID
    site_id: uuid.UUID
    enrollment_code: str = Field(description="Shown once. Single use. Expires.")
    expires_at: datetime


class EnrollmentRequest(MachineInbound):
    """Collector -> API, authenticated by the enrollment code only. No org/site fields: they come from the grant."""
    enrollment_code: Annotated[str, Field(min_length=32, max_length=256)]
    collector_version: Annotated[str, Field(pattern=r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")]
    host_fingerprint: Annotated[str, Field(min_length=16, max_length=128,
                                           description="Stable host id (e.g. sha256 of machine-id); binds the credential to one host")]
    capabilities: Annotated[list[Capability], Field(min_length=1)]


class EnrollmentResponse(MachineOutbound):
    identity_id: uuid.UUID
    machine_credential: str = Field(description="nsk_<id>.<secret>; shown once; store with 0600 permissions")
    site_id: uuid.UUID
    granted_capabilities: list[Capability]
    config_version: int


# ---------------------------------------------------------------- heartbeat & configuration
class CollectorHealth(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILING = "failing"


class CollectorHeartbeat(MachineInbound):
    sent_at: datetime
    collector_version: str
    config_version: int = Field(ge=0)
    health: CollectorHealth
    queue_depth: int = Field(ge=0)
    dropped_since_last: int = Field(ge=0, default=0)
    sources_active: int = Field(ge=0, default=0)
    problems: Annotated[list[ShortText], Field(max_length=20)] = []


class HeartbeatAck(MachineOutbound):
    server_time: datetime
    latest_config_version: int
    rotate_credential_by: datetime | None = None
    revoked: Literal[False] = False  # a revoked identity gets 401, never an ack


class SourceDefinition(Contract):
    source_id: uuid.UUID
    type: Literal["syslog_udp", "syslog_tcp", "syslog_tls", "file", "windows_event"]
    listen_port: Annotated[int, Field(ge=1, le=65535)] | None = None
    path: ShortText | None = None
    allowed_senders: Annotated[list[str], Field(max_length=256)] = Field(
        default=[], description="CIDRs within the collector's site allowed to send; empty = none")

    @field_validator("allowed_senders")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(c, strict=False)) for c in v]


class CollectorConfig(MachineOutbound):
    config_version: int
    issued_at: datetime
    sources: list[SourceDefinition]
    telemetry_max_batch: Annotated[int, Field(ge=1, le=1000)] = 500
    telemetry_max_rate_per_minute: Annotated[int, Field(ge=1)] = 60_000
    signature: str = Field(description="Detached signature over the canonical JSON of this document (algorithm per ADR)")


# ---------------------------------------------------------------- telemetry
class TelemetryEvent(Contract):
    event_id: Annotated[str, Field(min_length=8, max_length=128, description="Collector-unique id; dedupe key with the identity")]
    observed_at: datetime
    source_id: uuid.UUID
    sender: SiteScopedAddress
    format: Literal["syslog_rfc5424", "syslog_rfc3164", "cef", "leef", "json", "windows_xml"]
    raw: Annotated[str, Field(max_length=32_768, description="Raw event, capped at 32 KB (legacy ingest cap)")]
    # API rule (not expressible in the schema): sender.site_id MUST equal the authenticated identity's
    # site; otherwise the event is quarantined, never attributed to another site or organisation.


class TelemetryBatch(MachineInbound):
    batch_id: IdempotencyKey
    sent_at: datetime
    events: Annotated[list[TelemetryEvent], Field(min_length=1, max_length=1000)]


class TelemetryAck(MachineOutbound):
    batch_id: str
    accepted: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    rejected: int = Field(ge=0)
    quarantined: int = Field(ge=0, description="Stored but not attributable (e.g. sender outside the site's networks)")
    durable: Literal[True] = Field(default=True, description="An ack is only sent once the batch is durably stored")


# ---------------------------------------------------------------- credentials
class CredentialRotationRequest(MachineInbound):
    request_id: IdempotencyKey


class CredentialRotationResponse(MachineOutbound):
    machine_credential: str
    previous_valid_until: datetime = Field(description="Overlap window; the old credential stops working after this")


class CredentialRevocation(Contract):
    """Operator action (human API). Effective immediately; audited."""
    identity_id: uuid.UUID
    reason: Annotated[str, Field(min_length=3, max_length=500)]


# ---------------------------------------------------------------- scan connectivity & discovery
class ScanConnectivityAssignment(MachineOutbound):
    """Tells a collector with SCAN_RELAY which APPROVED scan jobs it may relay. Derived from VMS scope approvals."""
    assignment_id: uuid.UUID
    scan_job_id: uuid.UUID
    targets: Annotated[list[SiteScopedAddress], Field(min_length=1, max_length=4096)]
    allowed_ports: Annotated[list[Annotated[int, Field(ge=1, le=65535)]], Field(max_length=1024)] = []
    window_start: datetime
    window_end: datetime
    scope_approval_id: uuid.UUID

    @model_validator(mode="after")
    def _window(self):
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        if len({t.site_id for t in self.targets}) != 1:
            raise ValueError("an assignment covers exactly one site")
        return self


class DiscoveredHost(Contract):
    address: SiteScopedAddress
    mac: Annotated[str, Field(pattern=r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")] | None = None
    open_ports: Annotated[list[Annotated[int, Field(ge=1, le=65535)]], Field(max_length=1024)] = []
    observed_at: datetime
    method: Literal["arp", "icmp", "tcp_connect", "passive"]


class DiscoveryReport(MachineInbound):
    report_id: IdempotencyKey
    hosts: Annotated[list[DiscoveredHost], Field(max_length=10_000)]


class CollectorRecord(Internal):
    """Stored view of a collector (internal; org_id is the identity's, never client-supplied)."""
    identity_id: uuid.UUID
    org_id: uuid.UUID
    site_id: uuid.UUID
    status: Literal["active", "revoked"]
    capabilities: list[Capability]
    last_heartbeat_at: datetime | None = None
