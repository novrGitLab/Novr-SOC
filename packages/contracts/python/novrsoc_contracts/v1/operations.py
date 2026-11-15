"""Operations contracts v1 (platform-owned, shared by workstreams A, B, C, E).

Every background component (VMS worker, SOAR worker, forwarder, collector, job runner, backup agent)
reports with the same shapes, so Platform Health (workstream E) can show honest states for all of them.
  * Machine heartbeats are MACHINE-INBOUND: no organisation field; identity comes from the credential.
  * Every scheduled or queued unit of work is a JobRun with an idempotency key and a terminal state.
  * Failure behaviour is explicit: retryable vs permanent, with the next attempt time.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .common import Contract, IdempotencyKey, Internal, MachineInbound, ShortText


class ComponentKind(str, Enum):
    API = "api"
    VMS_WORKER = "vms_worker"
    SOAR_WORKER = "soar_worker"
    FORWARDER = "forwarder"
    COLLECTOR = "collector"
    JOB_RUNNER = "job_runner"
    BACKUP_AGENT = "backup_agent"
    AI_GATEWAY = "ai_gateway"


class HealthState(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILING = "failing"
    UNCONFIGURED = "unconfigured"


class DependencyCheck(Contract):
    name: Annotated[str, Field(pattern=r"^[a-z0-9_.-]{2,40}$")]
    state: HealthState
    detail: ShortText = Field(default="", description="Never a secret, URL with credentials, or raw response body")


class ComponentHeartbeat(MachineInbound):
    """Sent by a background component every <= 60 s. Identity (and organisation, for tenant-bound
    components) comes from the authenticated machine credential."""
    sent_at: datetime
    component_version: Annotated[str, Field(pattern=r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")]
    state: HealthState
    queue_depth: int = Field(ge=0, default=0)
    in_flight: int = Field(ge=0, default=0)
    dependencies: Annotated[list[DependencyCheck], Field(max_length=20)] = []


class ComponentStatus(Contract):
    """Read model for Platform Health. `stale` when no heartbeat arrived within 3 intervals."""
    component: ComponentKind
    identity_id: uuid.UUID | None = None
    state: HealthState | Literal["stale", "never_seen"]
    last_heartbeat_at: datetime | None = None
    version: ShortText | None = None
    dependencies: list[DependencyCheck] = []


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobRun(Internal):
    """One unit of scheduled or queued work. Unique (job_type, idempotency_key): a repeat is a no-op."""
    id: uuid.UUID
    org_id: uuid.UUID | None = Field(description="Set for tenant work; null only for platform-wide jobs")
    job_type: Annotated[str, Field(pattern=r"^[a-z0-9_.]{3,60}$")]
    idempotency_key: IdempotencyKey
    state: JobState
    attempt: int = Field(ge=1, default=1)
    max_attempts: int = Field(ge=1, le=10, default=3)
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    failure: Literal["retryable", "permanent"] | None = None
    failure_reason: ShortText = ""
    next_attempt_at: datetime | None = None

    @model_validator(mode="after")
    def _consistent(self):
        terminal = self.state in (JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED)
        if terminal and self.finished_at is None:
            raise ValueError("a terminal job has finished_at")
        if self.state == JobState.FAILED and self.failure is None:
            raise ValueError("a failed job says whether the failure is retryable or permanent")
        if self.failure == "retryable" and self.state == JobState.FAILED and self.attempt < self.max_attempts \
                and self.next_attempt_at is None:
            raise ValueError("a retryable failure with attempts left needs next_attempt_at")
        if self.attempt > self.max_attempts:
            raise ValueError("attempt exceeds max_attempts")
        return self
