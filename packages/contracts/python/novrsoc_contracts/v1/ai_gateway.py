"""AI Gateway contracts v1: authorised local inference through FastAPI.

The gateway is the ONLY path to the inference backend (Ollama behind an authenticated proxy). Ollama is
never reachable from the internet or the browser.

Two separate lanes:
  * general            general-purpose text inference. Gateway API key with scope `inference:general`.
                       No tenant data, no context assembly, no tools. Not organisation-bound.
  * security_analysis  privileged cybersecurity analysis (NHAI). A signed-in user with `nhai:analyze`
                       in the active organisation, OR an organisation-bound key with scope
                       `analysis:security` (for internal workers). Context is assembled server-side from
                       that organisation only. Separate model allowlist, quota, concurrency pool and audit.
Keys: `ngk_<key-id-hex>.<secret>`; secret ≥ 32 random bytes; only SHA-256 stored; shown once; revocable;
expiring. No production key is issued in Phase 2.5.
Proposed permissions (not seeded yet): `nhai:analyze` (analysts and managers), `ai_gateway:manage` (managers).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .common import Contract, Internal, ShortText

KEY_PATTERN = r"^ngk_[0-9a-f]{32}\.[A-Za-z0-9_-]{43,}$"


class Lane(str, Enum):
    GENERAL = "general"
    SECURITY_ANALYSIS = "security_analysis"


class KeyScope(str, Enum):
    INFERENCE_GENERAL = "inference:general"
    ANALYSIS_SECURITY = "analysis:security"


SCOPE_LANE = {KeyScope.INFERENCE_GENERAL: Lane.GENERAL, KeyScope.ANALYSIS_SECURITY: Lane.SECURITY_ANALYSIS}


class Quota(Contract):
    requests_per_minute: Annotated[int, Field(ge=1, le=600)]
    tokens_per_day: Annotated[int, Field(ge=1_000, le=10_000_000)]
    max_concurrency: Annotated[int, Field(ge=1, le=8)]


class GatewayKeyCreate(Contract):
    """Manager action (ai_gateway:manage). The organisation is the ACTIVE organisation for analysis keys."""
    name: Annotated[str, Field(min_length=3, max_length=120)]
    scopes: Annotated[list[KeyScope], Field(min_length=1, max_length=2)]
    allowed_models: Annotated[list[Annotated[str, Field(pattern=r"^[a-z0-9._-]+:[a-z0-9._-]+$")]], Field(min_length=1, max_length=10)]
    quota: Quota
    expires_at: datetime
    purpose: Annotated[str, Field(min_length=10, max_length=500)]

    @model_validator(mode="after")
    def _single_lane(self):
        if len(set(self.scopes)) != len(self.scopes):
            raise ValueError("duplicate scope")
        if len(self.scopes) > 1:
            raise ValueError("a key serves exactly one lane: general and security analysis are separate keys")
        return self


class GatewayKeyIssued(Contract):
    key_id: uuid.UUID
    key: Annotated[str, Field(pattern=KEY_PATTERN, description="Shown ONCE. Only its SHA-256 is stored")]
    expires_at: datetime


class GatewayKey(Contract):
    """Stored view; never contains the secret."""
    key_id: uuid.UUID
    name: str
    prefix: Annotated[str, Field(pattern=r"^ngk_[0-9a-f]{8}$")]
    lane: Lane
    org_id: uuid.UUID | None = Field(description="Required for security_analysis keys; null for general keys")
    allowed_models: list[str]
    quota: Quota
    created_by: uuid.UUID
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None

    @model_validator(mode="after")
    def _tenant_binding(self):
        if self.lane == Lane.SECURITY_ANALYSIS and self.org_id is None:
            raise ValueError("a security-analysis key is bound to exactly one organisation")
        if self.lane == Lane.GENERAL and self.org_id is not None:
            raise ValueError("a general-inference key carries no organisation (it must not see tenant data)")
        return self


class GatewayKeyRevoke(Contract):
    key_id: uuid.UUID
    reason: Annotated[str, Field(min_length=3, max_length=500)]


class ChatTurn(Contract):
    role: Literal["system", "user", "assistant"]
    content: Annotated[str, Field(min_length=1, max_length=16_000)]


class GeneralInferenceRequest(Contract):
    """Lane `general`. No tenant identifiers or context; the gateway does not enrich it."""
    model: Annotated[str, Field(pattern=r"^[a-z0-9._-]+:[a-z0-9._-]+$")]
    messages: Annotated[list[ChatTurn], Field(min_length=1, max_length=40)]
    max_tokens: Annotated[int, Field(ge=1, le=2048)] = 512
    temperature: Annotated[float, Field(ge=0, le=1.5)] = 0.2


class GeneralInferenceResponse(Contract):
    request_id: str
    model: str
    text: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    latency_ms: int = Field(ge=0)


class LanePolicy(Contract):
    lane: Lane
    allowed_models: Annotated[list[str], Field(min_length=1)]
    timeout_seconds: Annotated[float, Field(ge=1, le=300)]
    max_input_chars: Annotated[int, Field(ge=100, le=200_000)]
    max_output_tokens: Annotated[int, Field(ge=16, le=8192)]
    max_concurrency: Annotated[int, Field(ge=1, le=16)] = Field(description="Shared by every caller of the lane")


class RejectReason(str, Enum):
    KEY_INVALID = "key_invalid"
    KEY_REVOKED_OR_EXPIRED = "key_revoked_or_expired"
    WRONG_LANE = "wrong_lane"
    MODEL_NOT_ALLOWED = "model_not_allowed"
    RATE_LIMITED = "rate_limited"
    DAILY_QUOTA_EXHAUSTED = "daily_quota_exhausted"
    CONCURRENCY_LIMIT = "concurrency_limit"
    INPUT_TOO_LARGE = "input_too_large"
    TIMEOUT = "timeout"
    BACKEND_UNAVAILABLE = "backend_unavailable"


class UsageEvent(Internal):
    """One per gateway request (allowed or rejected). Prompt and output TEXT are never stored here;
    a SHA-256 of the prompt allows correlation without retaining content."""
    request_id: str
    occurred_at: datetime
    lane: Lane
    key_id: uuid.UUID | None = None
    user_id: uuid.UUID | None = None
    org_id: uuid.UUID | None = None
    model: ShortText
    outcome: Literal["ok", "rejected", "timeout", "backend_error"]
    reject_reason: RejectReason | None = None
    prompt_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    prompt_tokens: int = Field(ge=0, default=0)
    completion_tokens: int = Field(ge=0, default=0)
    latency_ms: int = Field(ge=0, default=0)

    @model_validator(mode="after")
    def _caller(self):
        if self.key_id is None and self.user_id is None:
            raise ValueError("every request is attributed to a key or a user")
        if self.lane == Lane.SECURITY_ANALYSIS and self.org_id is None and self.outcome != "rejected":
            # A refused caller may have no organisation (that can be why it was refused); anything that
            # reached the model is always attributed to one.
            raise ValueError("security-analysis usage is always attributed to an organisation")
        if (self.outcome == "rejected") != (self.reject_reason is not None):
            raise ValueError("reject_reason is set exactly when the outcome is rejected")
        return self


class QuotaStatus(Contract):
    key_id: uuid.UUID
    requests_this_minute: int = Field(ge=0)
    tokens_today: int = Field(ge=0)
    quota: Quota
