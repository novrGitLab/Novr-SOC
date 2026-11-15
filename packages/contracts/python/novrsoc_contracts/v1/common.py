"""Shared building blocks for every v1 contract.

Rules every contract follows (enforced by tests in packages/contracts/tests):
  * Models reject unknown fields (extra="forbid"), so a typo or an injected field is an error, not ignored.
  * MACHINE-INBOUND models (sent by a collector, worker, forwarder or gateway) never carry an
    organisation id: the API derives the organisation from the authenticated service identity.
  * Network addresses are site-scoped: (site_id, ip). Two sites may hold the same private address.
  * State-changing machine and SOAR requests carry an idempotency key.
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, ClassVar, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

CONTRACT_VERSION = "1.0.0"

IdempotencyKey = Annotated[str, Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$",
                                      description="Client-chosen key; a repeat with the same key returns the first result")]
Slug = Annotated[str, Field(min_length=2, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
ShortText = Annotated[str, Field(max_length=200)]
LongText = Annotated[str, Field(max_length=4000)]


class Direction(str, Enum):
    API = "api"                        # request/response of the public HTTP API (human callers)
    MACHINE_INBOUND = "machine_inbound"  # sent TO the API by a service identity
    MACHINE_OUTBOUND = "machine_outbound"  # sent BY the API to a service identity
    INTERNAL = "internal"              # between V2 components through the database


class Contract(BaseModel):
    """Base for all contracts."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True, use_enum_values=False)
    direction: ClassVar[Direction] = Direction.API


class MachineInbound(Contract):
    direction: ClassVar[Direction] = Direction.MACHINE_INBOUND


class MachineOutbound(Contract):
    direction: ClassVar[Direction] = Direction.MACHINE_OUTBOUND


class Internal(Contract):
    direction: ClassVar[Direction] = Direction.INTERNAL


class ErrorDetail(Contract):
    code: str = Field(description="Stable machine-readable code, e.g. forbidden, validation_error")
    message: str
    request_id: str
    details: Any | None = None


class ErrorResponse(Contract):
    error: ErrorDetail


class HonestState(str, Enum):
    """What a UI must distinguish instead of one 'not connected' (audit 08 §5)."""
    OK = "ok"
    EMPTY = "empty"
    BACKEND_UNREACHABLE = "backend_unreachable"
    DATABASE_UNCONFIGURED = "database_unconfigured"
    SCHEMA_MISSING = "schema_missing"
    INTEGRATION_UNCONFIGURED = "integration_unconfigured"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    ERROR = "error"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


T = TypeVar("T")


class Page(Contract, Generic[T]):
    items: list[T]
    next_cursor: str | None = Field(default=None, description="Opaque; absent on the last page")
    limit: int = Field(ge=1, le=500)


class SiteScopedAddress(Contract):
    """An IP address is only meaningful inside a site: 10.0.0.5 at site A is not 10.0.0.5 at site B."""
    site_id: uuid.UUID
    ip: str
    hostname: ShortText | None = None

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        return str(ipaddress.ip_address(v))

    @property
    def is_private(self) -> bool:
        return ipaddress.ip_address(self.ip).is_private


class ActorRef(Contract):
    type: Literal["user", "service", "system"]
    id: uuid.UUID | None = None
    label: ShortText = ""


class ResourceRef(Contract):
    type: Annotated[str, Field(pattern=r"^[a-z_]{2,40}$")]
    id: ShortText


class Timestamped(Contract):
    created_at: datetime
