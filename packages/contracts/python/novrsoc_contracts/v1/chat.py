"""NovrChat (consolidation): a conversational assistant over the active organization's own records.

How an answer is made:
  1. The question is routed (deterministically) to read-only tools: alerts, cases, assets, vulnerabilities, posture,
     threat intelligence, SLA, reports. Each tool checks the caller's permission and runs under the organization's
     row-level security. A tool the caller may not use reports `not_permitted` and returns nothing.
  2. The retrieved records become the answer's citations (C1, C2, ...). The immediate answer restates them only.
  3. When NHAI is configured, a `chat_answer` NHAI job drafts a prose answer from the SAME citations, validated like
     every NHAI result (grounding, no invented indicators). It is labelled as an AI draft.
NovrChat never changes a record, except a report it generates on request for a caller with reports:manage.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from .common import Contract, ResourceRef
from .nhai import NhaiJob


class ChatCitation(Contract):
    citation_id: Annotated[str, Field(pattern=r"^C[1-9][0-9]{0,3}$")]
    ref: ResourceRef
    label: str
    excerpt: Annotated[str, Field(max_length=1000)]
    href: str = ""


class ChatToolCall(Contract):
    tool: str
    permission: str
    state: Literal["ok", "empty", "not_permitted", "unavailable"]
    detail: str = ""
    records: int = Field(ge=0, default=0)


class ChatMessageView(Contract):
    id: uuid.UUID
    role: Literal["user", "assistant"]
    content: str
    tools: list[ChatToolCall] = []
    citations: list[ChatCitation] = []
    state: Literal["complete", "refused"]
    nhai: NhaiJob | None = Field(default=None, description="The AI-drafted answer job, when NHAI is configured")
    created_at: datetime


class ChatConversationView(Contract):
    id: uuid.UUID
    title: str
    created_at: datetime
    updated_at: datetime
    messages: list[ChatMessageView] = []


class ChatConversationList(Contract):
    items: list[ChatConversationView]


class ChatConversationCreate(Contract):
    title: Annotated[str, Field(min_length=1, max_length=200)] = "New conversation"


class ChatMessageCreate(Contract):
    content: Annotated[str, Field(min_length=1, max_length=2000)]


class ChatExchange(Contract):
    question: ChatMessageView
    answer: ChatMessageView
