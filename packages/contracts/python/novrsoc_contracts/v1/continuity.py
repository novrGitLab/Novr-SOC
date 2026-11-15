"""Data continuity (consolidation): recovery plans, recovery requests, verification and evidence.

Honest boundaries:
  * `novrsoc_platform_backup` plans cover NovrSOC's own database (encrypted logical backups and restore drills run by
    the platform administrator on Server 2). That is the only connected backup system in this installation.
  * `external_provider` and `manual_procedure` plans are administrative workflows: NovrSOC records the request,
    decision, progress and evidence, but it does not run the recovery and cannot recover data on its own.
  * A request can end as `not_recoverable`: deleted data cannot be recovered without an appropriate backup.
Achieved RPO = loss detected - point recovered to; achieved RTO = completion - submission.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from .common import ActorRef, Contract

BackupSource = Literal["novrsoc_platform_backup", "external_provider", "manual_procedure"]
RequestStatus = Literal["submitted", "assessing", "approved", "in_progress", "completed", "rejected", "not_recoverable"]


class RecoveryPlanCreate(Contract):
    name: Annotated[str, Field(min_length=3, max_length=200)]
    scope: Annotated[str, Field(min_length=3, max_length=4000)]
    backup_source: BackupSource
    provider_name: Annotated[str, Field(max_length=200)] = ""
    rpo_minutes: Annotated[int, Field(ge=1, le=525600)] | None = None
    rto_minutes: Annotated[int, Field(ge=1, le=525600)] | None = None
    procedure: Annotated[str, Field(max_length=8000)] = ""
    owning_unit: Annotated[str, Field(max_length=200)] = ""

    @model_validator(mode="after")
    def _provider(self):
        if self.backup_source == "external_provider" and len(self.provider_name.strip()) < 2:
            raise ValueError("an external provider plan names its provider")
        return self


class RecoveryPlanView(RecoveryPlanCreate):
    id: uuid.UUID
    last_tested_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    execution: str = Field(description="What NovrSOC can actually do for this plan")


class RecoveryPlanList(Contract):
    items: list[RecoveryPlanView]


class RecoveryPlanTested(Contract):
    tested_at: datetime
    note: Annotated[str, Field(min_length=3, max_length=2000)]


class RecoveryRequestCreate(Contract):
    plan_id: uuid.UUID | None = None
    title: Annotated[str, Field(min_length=3, max_length=200)]
    description: Annotated[str, Field(min_length=10, max_length=4000)]
    affected_data: Annotated[str, Field(min_length=3, max_length=2000)]
    loss_detected_at: datetime
    requested_recovery_point: datetime | None = None


class RecoveryDecision(Contract):
    """assess / approve / reject / not_recoverable, by someone other than the requester (recovery:manage)."""
    decision: Literal["assess", "approve", "reject", "not_recoverable"]
    reason: Annotated[str, Field(min_length=5, max_length=2000)]
    backup_reference: Annotated[str, Field(max_length=300)] = ""


class RecoveryProgress(Contract):
    status: Literal["in_progress", "completed"]
    note: Annotated[str, Field(min_length=3, max_length=4000)]
    recovered_point: datetime | None = None
    evidence: Annotated[list[Annotated[str, Field(max_length=500)]], Field(max_length=20)] = []


class RecoveryVerification(Contract):
    result: Literal["verified", "failed", "not_applicable"]
    note: Annotated[str, Field(min_length=5, max_length=2000)]


class RecoveryEventView(Contract):
    id: int
    occurred_at: datetime
    kind: Literal["submitted", "status_changed", "note", "evidence", "verification"]
    actor_label: str
    body: str
    details: dict[str, Any] = {}


class RecoveryRequestView(Contract):
    id: uuid.UUID
    plan_id: uuid.UUID | None = None
    plan_name: str | None = None
    backup_source: BackupSource | None = None
    title: str
    description: str
    affected_data: str
    loss_detected_at: datetime
    requested_recovery_point: datetime | None = None
    status: RequestStatus
    requested_by: ActorRef
    decided_by: ActorRef | None = None
    decision_reason: str | None = None
    backup_reference: str = ""
    recovered_point: datetime | None = None
    verification: Literal["pending", "verified", "failed", "not_applicable"]
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    achieved_rpo_minutes: int | None = None
    achieved_rto_minutes: int | None = None
    rpo_target_minutes: int | None = None
    rto_target_minutes: int | None = None
    events: list[RecoveryEventView] = []


class RecoveryRequestList(Contract):
    items: list[RecoveryRequestView]


class PlatformBackupState(Contract):
    visible: bool = Field(description="False when the caller may not read platform backup history")
    last_succeeded_at: datetime | None = None
    last_drill_at: datetime | None = None
    last_drill_status: str | None = None
    note: str


class ContinuityOverview(Contract):
    generated_at: datetime
    platform_backups: PlatformBackupState
    plans: int = Field(ge=0)
    plans_untested_90d: int = Field(ge=0)
    open_requests: int = Field(ge=0)
    completed_requests: int = Field(ge=0)
    not_recoverable: int = Field(ge=0)
    rpo_met: int = Field(ge=0)
    rpo_missed: int = Field(ge=0)
    rto_met: int = Field(ge=0)
    rto_missed: int = Field(ge=0)
