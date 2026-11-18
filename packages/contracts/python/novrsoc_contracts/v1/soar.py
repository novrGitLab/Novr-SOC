"""SOAR contracts v1 (contract only; the SOAR worker is built by workstream A).

Behaviour carried from the legacy approval contract and its later hardening:
  * Consequential actions (block_ip, isolate_agent, disable_account) ALWAYS need a human approval
    by a holder of response:approve. Self-approval is refused.
  * At execution time the worker re-checks that the target still belongs to the organisation.
  * Outcomes use the honest vocabulary: succeeded / skipped_not_configured / failed / cancelled.
  * Every execution request carries an idempotency key; a retry never runs an action twice.
  * Phase 2 rule: execution mode is dry_run only. "live" is defined so the contract is stable, but
    the API refuses it until the owner enables live response per organisation (D-08).
The legacy integratord containment hook is NOT part of this contract and must never feed it.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from .common import ActorRef, Contract, IdempotencyKey, Internal, LongText, Severity, ShortText

CONSEQUENTIAL_ACTIONS = frozenset({"block_ip", "isolate_agent", "disable_account"})


class ActionType(str, Enum):
    ENRICH_IOCS = "enrich_iocs"
    NOTIFY_EMAIL = "notify_email"
    NOTIFY_CISO = "notify_ciso"
    CREATE_TASK = "create_task"
    BLOCK_IP = "block_ip"
    ISOLATE_AGENT = "isolate_agent"
    DISABLE_ACCOUNT = "disable_account"

    @property
    def consequential(self) -> bool:
        return self.value in CONSEQUENTIAL_ACTIONS


class ExecutionMode(str, Enum):
    DRY_RUN = "dry_run"
    LIVE = "live"


# ---------------------------------------------------------------- alert -> case
class AlertToCasePromotion(Contract):
    """Analyst (cases:write) promotes stored alerts to a case. Dedupe key: (org, source, source_id)."""
    alert_ids: Annotated[list[uuid.UUID], Field(min_length=1, max_length=500)]
    title: Annotated[str, Field(min_length=3, max_length=200)]
    severity: Severity
    source: Annotated[str, Field(pattern=r"^[a-z0-9_-]{2,40}$")] = "alert"
    source_id: Annotated[str, Field(min_length=1, max_length=200)] = Field(
        description="With org and source, the case dedupe key; a repeat returns the existing case")
    assignee_id: uuid.UUID | None = None
    summary: LongText = ""


class CasePromotionResult(Contract):
    case_id: uuid.UUID
    created: bool = Field(description="False when an existing case with the same dedupe key was returned")
    linked_alert_ids: list[uuid.UUID]


# ---------------------------------------------------------------- playbooks
class PlaybookStep(Contract):
    step_key: Annotated[str, Field(pattern=r"^[a-z0-9_]{2,60}$")]
    action: ActionType
    parameters: dict[str, str | int | bool | list[str]] = {}
    timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 120
    max_attempts: Annotated[int, Field(ge=1, le=5)] = 3

    @property
    def requires_approval(self) -> bool:
        return self.action.consequential


class PlaybookExecutionRequest(Contract):
    """Requested by an analyst/manager for a case. Creates a run in state pending (or awaiting_approval)."""
    idempotency_key: IdempotencyKey
    playbook_id: uuid.UUID
    playbook_version: int = Field(ge=1)
    case_id: uuid.UUID
    mode: ExecutionMode = ExecutionMode.DRY_RUN


class RunState(str, Enum):
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


ALLOWED_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.PENDING: frozenset({RunState.AWAITING_APPROVAL, RunState.RUNNING, RunState.CANCELLED}),
    RunState.AWAITING_APPROVAL: frozenset({RunState.RUNNING, RunState.CANCELLED}),
    RunState.RUNNING: frozenset({RunState.SUCCEEDED, RunState.FAILED, RunState.AWAITING_APPROVAL, RunState.CANCELLED}),
    RunState.SUCCEEDED: frozenset(), RunState.FAILED: frozenset(), RunState.CANCELLED: frozenset(),
}


class TaskExecution(Internal):
    """One step attempt, written by the SOAR worker (API reads). Unique (run_id, step_key, attempt)."""
    run_id: uuid.UUID
    step_key: str
    action: ActionType
    attempt: int = Field(ge=1, le=5)
    idempotency_key: IdempotencyKey = Field(description="Derived: <run idempotency key>:<step_key>; sent to connectors that support it")
    mode: ExecutionMode
    target: ShortText | None = None
    started_at: datetime


# ---------------------------------------------------------------- approvals
class ApprovalRequest(Contract):
    idempotency_key: IdempotencyKey
    run_id: uuid.UUID
    step_key: str
    action: ActionType
    target: Annotated[str, Field(min_length=1, max_length=200)]
    justification: Annotated[str, Field(min_length=10, max_length=2000)]
    requested_by: ActorRef

    @model_validator(mode="after")
    def _only_consequential(self):
        if not self.action.consequential:
            raise ValueError("only consequential actions are approval-gated")
        return self


class ApprovalDecision(Contract):
    approval_id: uuid.UUID
    decision: Literal["approve", "reject"]
    reason: Annotated[str, Field(min_length=3, max_length=2000)]
    decided_by: ActorRef
    requested_by: ActorRef = Field(description="Echoed from the request so self-approval is checked in the contract too")

    @model_validator(mode="after")
    def _no_self_approval(self):
        if self.decided_by.type != "user":
            raise ValueError("approvals are human decisions")
        if self.decided_by.id is not None and self.decided_by.id == self.requested_by.id:
            raise ValueError("self-approval is not allowed")
        return self


# ---------------------------------------------------------------- outcomes & retries
class OutcomeStatus(str, Enum):
    SUCCEEDED = "succeeded"
    SKIPPED_NOT_CONFIGURED = "skipped_not_configured"
    FAILED = "failed"
    CANCELLED = "cancelled"
    DRY_RUN = "dry_run"


class RetryPolicy(Contract):
    max_attempts: Annotated[int, Field(ge=1, le=5)] = 3
    initial_backoff_seconds: Annotated[int, Field(ge=1, le=600)] = 5
    max_backoff_seconds: Annotated[int, Field(ge=1, le=3600)] = 300
    retry_on: list[Literal["timeout", "connector_unavailable", "rate_limited"]] = ["timeout", "connector_unavailable"]


class ExecutionOutcome(Internal):
    run_id: uuid.UUID
    step_key: str
    attempt: int = Field(ge=1)
    status: OutcomeStatus
    mode: ExecutionMode
    message: ShortText
    retryable: bool = False
    next_attempt_at: datetime | None = None
    finished_at: datetime
    ownership_rechecked: bool = Field(description="Target re-verified as belonging to the organisation at execution time")

    @model_validator(mode="after")
    def _consistency(self):
        if self.mode == ExecutionMode.DRY_RUN and self.status == OutcomeStatus.SUCCEEDED:
            raise ValueError("a dry run reports status dry_run, never succeeded")
        if self.retryable and self.next_attempt_at is None:
            raise ValueError("a retryable outcome needs next_attempt_at")
        return self


class SoarAuditEvent(Internal):
    """Every state change of a run, approval or step is also an audit_events row with these actions."""
    action: Literal["SOAR_RUN_REQUESTED", "SOAR_RUN_STATE", "SOAR_APPROVAL_REQUESTED", "SOAR_APPROVAL_DECIDED",
                    "SOAR_STEP_EXECUTED", "SOAR_STEP_RETRY_SCHEDULED", "SOAR_LIVE_REFUSED", "SOAR_AUTOMATION_CHANGED",
                    "SOAR_AUTOMATIC_RUN", "SOAR_POLICY_AUTHORIZED", "SOAR_AUTOMATIC_CASE"]
    run_id: uuid.UUID
    step_key: str | None = None
    actor: ActorRef
    from_state: RunState | None = None
    to_state: RunState | None = None


# ---------------------------------------------------------------- Phase 6 pilot (additive): engine API views
PlaybookName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,59}$")]


class PlaybookTriggers(Contract):
    """Deterministic recommendation criteria matched against a case's alerts (never auto-executed)."""
    rule_ids: list[Annotated[str, Field(max_length=20)]] = []
    mitre: list[Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]] = []
    min_level: Annotated[int, Field(ge=0, le=16)] = 0


class PlaybookExecutionPolicy(Contract):
    """Consolidation: how an APPROVED playbook version may run. Live mode still needs the organization's response
    policy (live_enabled); this policy can only narrow that. `automatic`: the version may also be started by NovrSOAR
    automation when a new alert matches its triggers (the organization's automation must be on as well). A
    consequential step of an automatic run proceeds without a person only when the organization's policy
    pre-authorizes the action and every guard passes; otherwise it waits for a human approval."""
    modes: Annotated[list[ExecutionMode], Field(min_length=1, max_length=2)] = [ExecutionMode.DRY_RUN]
    min_case_severity: Literal["low", "medium", "high", "critical"] = "low"
    max_runs_per_day: Annotated[int, Field(ge=1, le=500)] = 20
    automatic: bool = False


class PlaybookCreate(Contract):
    name: PlaybookName
    title: Annotated[str, Field(min_length=3, max_length=200)]
    steps: Annotated[list[PlaybookStep], Field(min_length=1, max_length=20)]
    triggers: PlaybookTriggers = PlaybookTriggers()
    description: Annotated[str, Field(max_length=4000)] = ""
    execution_policy: PlaybookExecutionPolicy = PlaybookExecutionPolicy()


PlaybookStatus = Literal["draft", "validated", "pending_approval", "approved", "retired"]


class PlaybookValidation(Contract):
    valid: bool
    errors: list[Annotated[str, Field(max_length=300)]] = []
    warnings: list[Annotated[str, Field(max_length=300)]] = []
    checked_at: datetime


class PlaybookReview(Contract):
    """Approve or reject a version that is pending approval. The author can never approve their own version."""
    decision: Literal["approve", "reject"]
    note: Annotated[str, Field(min_length=3, max_length=2000)]


class PlaybookView(Contract):
    id: uuid.UUID
    name: str
    version: int
    title: str
    steps: list[PlaybookStep]
    triggers: PlaybookTriggers
    enabled: bool
    created_at: datetime
    status: PlaybookStatus = Field(default="draft", description="Consolidation: only an approved, enabled version can run")
    description: str = ""
    execution_policy: PlaybookExecutionPolicy = PlaybookExecutionPolicy()
    validation: PlaybookValidation | None = None
    created_by_label: str = ""
    approved_by: ActorRef | None = None
    approved_at: datetime | None = None
    review_note: str = ""


class PlaybookVersionList(Contract):
    name: str
    items: list[PlaybookView]


class PlaybookList(Contract):
    items: list[PlaybookView]


class SoarPolicyView(Contract):
    """The organization's response authorization. Empty allow-lists = nothing consequential may run."""
    allowed_actions: list[ActionType]
    allowed_agent_groups: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]]
    live_enabled: bool
    approval_ttl_minutes: Annotated[int, Field(ge=5, le=1440)]
    updated_at: datetime | None = None
    emergency_stop: bool = Field(default=False, description="Consolidation: when on, no run starts and nothing is dispatched")
    emergency_reason: str = ""
    emergency_at: datetime | None = None
    max_runs_per_hour: Annotated[int, Field(ge=1, le=500)] = 20
    max_dispatch_attempts: Annotated[int, Field(ge=1, le=10)] = 3
    automation: "SoarAutomationPolicy" = Field(default_factory=lambda: SoarAutomationPolicy(),
                                               description="Policy-driven orchestration (off by default)")
    automation_since: datetime | None = Field(default=None, description="When automation was last switched on: only alerts "
                                                                        "received after this are ever acted on")


ProtectedTarget = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:/\\-]{1,64}$")]


class SoarAutomationPolicy(Contract):
    """Policy-driven orchestration of one organization. Off by default.

    * `case_creation`: new alerts at or above `case_min_severity` open (or join) an automation case without a person.
    * `enabled`: approved playbook versions marked `automatic` start on matching new alerts.
    * `pre_authorized_actions`: consequential actions that may proceed WITHOUT a per-event human approval, and only when
      the detection confidence is at least `min_confidence`, the target comes from the alert's own evidence, its agent
      groups are authorized, it is not a protected target, and fewer than `max_dispatches_per_hour` automatic dispatches
      happened in the last hour. Each must also be in the policy's `allowed_actions`. Everything else waits for a person.
    * `protected_targets`: IP addresses or networks (CIDR), NovrAgent ids and account names that no response action
      (automatic or approved) may ever target."""
    enabled: bool = False
    case_creation: bool = False
    case_min_severity: Literal["low", "medium", "high", "critical"] = "high"
    pre_authorized_actions: list[ActionType] = []
    min_confidence: Annotated[int, Field(ge=0, le=100)] = 80
    max_dispatches_per_hour: Annotated[int, Field(ge=1, le=500)] = 20
    protected_targets: Annotated[list[ProtectedTarget], Field(max_length=200)] = []


SoarPolicyView.model_rebuild()


class SoarPolicyUpdate(Contract):
    allowed_actions: list[ActionType]
    allowed_agent_groups: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]]
    live_enabled: bool = False
    approval_ttl_minutes: Annotated[int, Field(ge=5, le=1440)] = 60
    max_runs_per_hour: Annotated[int, Field(ge=1, le=500)] = 20
    max_dispatch_attempts: Annotated[int, Field(ge=1, le=10)] = 3
    automation: SoarAutomationPolicy | None = Field(default=None, description="Omitted: the automation policy is unchanged")


StepState = Literal["pending", "awaiting_approval", "rejected", "expired", "dispatched", "succeeded", "failed", "dry_run",
                    "skipped_not_configured", "refused_by_policy"]


class ExecutionReceipt(Contract):
    """The Server 1 bridge's signed answer, verified by the engine before it is stored."""
    request_id: uuid.UUID
    status: Literal["executed", "dry_run", "rejected", "failed"]
    reason: ShortText
    adapter: str
    command: str | None = None
    executed_at: datetime
    replayed: bool = False


class StepView(Contract):
    id: uuid.UUID
    step_key: str
    action: ActionType
    target: str | None
    state: StepState
    message: str
    request_id: uuid.UUID | None = None
    receipt: ExecutionReceipt | None = None
    approval_id: uuid.UUID | None = None
    authorization: Literal["human", "policy"] | None = Field(default=None, description="Who authorized a consequential step: "
                                                                                       "a person, or the pre-authorization policy")
    request: dict[str, Any] | None = Field(default=None, description="The exact request body signed and sent to NovrSOAR "
                                                                     "(no secret is part of it)")


class ApprovalView(Contract):
    id: uuid.UUID
    run_id: uuid.UUID
    step_key: str
    action: ActionType
    target: str
    justification: str
    requested_by: ActorRef
    decision: Literal["approve", "reject"] | None = None
    decided_by: ActorRef | None = None
    reason: str | None = None
    expires_at: datetime
    created_at: datetime
    authorization: Literal["human", "policy"] = "human"


class ApprovalList(Contract):
    items: list[ApprovalView]


class ApprovalDecisionRequest(Contract):
    """The human decision. The decider is the signed-in user (never the requester)."""
    decision: Literal["approve", "reject"]
    reason: Annotated[str, Field(min_length=3, max_length=2000)]


class RunView(Contract):
    id: uuid.UUID
    playbook_id: uuid.UUID
    playbook_name: str
    playbook_version: int
    case_id: uuid.UUID
    mode: ExecutionMode
    state: RunState
    requested_by: ActorRef
    created_at: datetime
    updated_at: datetime
    steps: list[StepView] = []
    origin: Literal["manual", "automatic"] = "manual"
    confidence: int | None = Field(default=None, ge=0, le=100, description="Automatic runs: the detection confidence")
    trigger_alert_id: uuid.UUID | None = None


class RunList(Contract):
    items: list[RunView]


class RunCreate(Contract):
    """PlaybookExecutionRequest plus the human justification recorded on any approval it creates."""
    idempotency_key: IdempotencyKey
    playbook_id: uuid.UUID
    playbook_version: int = Field(ge=1)
    case_id: uuid.UUID
    mode: ExecutionMode = ExecutionMode.DRY_RUN
    justification: Annotated[str, Field(min_length=10, max_length=2000)]


class PlaybookRecommendation(Contract):
    playbook: PlaybookView
    matched_on: list[ShortText]
    proposed_targets: dict[str, ShortText] = {}


class RecommendationList(Contract):
    case_id: uuid.UUID
    items: list[PlaybookRecommendation]


# ---------------------------------------------------------------- consolidation: SOAR operations centre
class EmergencyStopRequest(Contract):
    """Turn the organization's emergency stop on or off (soar:manage). Always audited, always with a reason."""
    active: bool
    reason: Annotated[str, Field(min_length=10, max_length=500)]


class SoarTimelineEntry(Contract):
    at: datetime
    category: Literal["execution", "approval", "policy", "playbook", "ai_analysis"]
    action: str
    actor_label: str
    resource_id: str
    summary: str
    outcome: Literal["success", "denied", "failure", "pending", "refused"]


class SoarOperations(Contract):
    """The operations centre view. `ai_analysis` entries are analysis only; execution entries come from the engine."""
    generated_at: datetime
    emergency_stop: bool
    emergency_reason: str
    live_enabled: bool
    awaiting_approval: int = Field(ge=0)
    running: int = Field(ge=0)
    completed_24h: int = Field(ge=0)
    failed_24h: int = Field(ge=0)
    dispatched_without_receipt: int = Field(ge=0)
    refused_24h: int = Field(ge=0)
    human_intervention: int = Field(ge=0, description="Runs waiting for a person: approvals or re-dispatch")
    runs_last_hour: int = Field(ge=0)
    max_runs_per_hour: int
    approved_playbooks: int = Field(ge=0)
    pending_playbook_reviews: int = Field(ge=0)
    timeline: list[SoarTimelineEntry]
    automation_enabled: bool = False
    automatic_runs_24h: int = Field(default=0, ge=0)
    policy_authorized_24h: int = Field(default=0, ge=0, description="Consequential steps dispatched under pre-authorization")
    automatic_cases_24h: int = Field(default=0, ge=0)


class AutomationDecision(str, Enum):
    CASE_CREATED = "case_created"
    CASE_JOINED = "case_joined"
    RUN_STARTED = "run_started"
    SKIPPED_EMERGENCY_STOP = "skipped_emergency_stop"
    SKIPPED_LIMIT = "skipped_limit"
    SKIPPED_SEVERITY = "skipped_severity"
    FAILED = "failed"


class AutomationEventView(Contract):
    """One decision NovrSOAR automation took for one new alert (and playbook, when one matched)."""
    id: uuid.UUID
    created_at: datetime
    alert_id: uuid.UUID
    playbook_name: str = ""
    decision: AutomationDecision
    confidence: int = Field(ge=0, le=100)
    confidence_factors: list[str] = []
    case_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None
    detail: str = ""


class AutomationEventList(Contract):
    items: list[AutomationEventView]
    enabled: bool
    case_creation: bool
    since: datetime | None = None


class AiActivityView(Contract):
    id: int
    occurred_at: datetime
    kind: Literal["analysis_requested", "analysis_completed", "analysis_failed", "recommendation", "proposed_action", "review",
                  "chat_question", "chat_answer", "chat_refused"]
    module: str
    task: str
    subject_type: str
    subject_id: str
    actor: ActorRef
    model: str
    outcome: Literal["success", "failure", "pending", "refused"]
    summary: str
    nhai_job_id: uuid.UUID | None = None
    details: dict[str, Any] = {}


class AiActivityList(Contract):
    items: list[AiActivityView]
    note: str = "AI analysis only. Nothing listed here executed a response action; execution is recorded by the SOAR engine."
