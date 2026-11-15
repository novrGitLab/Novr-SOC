"""Executive overview and security posture (consolidation).

Every measurement is explainable: its value, the numerator and denominator it came from, the formula, the weight it
carries in the posture score, and a link to the records behind it. A measurement whose data is missing is
`unavailable` with the reason; it is never counted as 0 or 100. The posture score is computed only from the available
measurements and is withheld (`insufficient_data`) when they cover less than half of the total weight.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import Field

from .common import Contract
from .endpoints import ConnectorState


class Measure(Contract):
    key: str
    label: str
    value: float | None = None
    unit: Literal["percent", "count", "minutes", "score"]
    state: Literal["ok", "unavailable", "not_permitted"]
    reason: str = ""
    numerator: int | None = None
    denominator: int | None = None
    weight: float = Field(ge=0, le=1, default=0)
    higher_is_better: bool = True
    formula: str = ""
    evidence_href: str = ""


class PostureScore(Contract):
    score: int | None = Field(default=None, ge=0, le=100)
    state: Literal["ok", "insufficient_data"]
    coverage_percent: int = Field(ge=0, le=100)
    method: str
    contributing: list[str] = []
    excluded: list[str] = []


class TrendPoint(Contract):
    period_start: date
    values: dict[str, int]


class Priority(Contract):
    kind: str
    title: str
    detail: str
    severity: Literal["critical", "high", "medium", "low"]
    href: str


class ExecutiveOverview(Contract):
    generated_at: datetime
    organization: str
    score: PostureScore
    kpis: list[Measure]
    measures: list[Measure]
    vulnerability_trend: list[TrendPoint]
    incident_trend: list[TrendPoint]
    findings_by_severity: dict[str, int] = {}
    assets_by_criticality: dict[str, int] = {}
    remediation_by_state: dict[str, int] = {}
    priorities: list[Priority]
    sources: list[ConnectorState] = []


class PostureGap(Contract):
    key: str
    title: str
    detail: str
    severity: Literal["critical", "high", "medium", "low"]
    href: str


class ControlArea(Contract):
    key: str
    title: str
    description: str
    measures: list[Measure]


class CompliancePolicyRow(Contract):
    policy_id: str
    name: str
    endpoints: int = Field(ge=0)
    average_score: int | None = None
    failed_checks: int = Field(ge=0)
    passed_checks: int = Field(ge=0)


class ComplianceView(Contract):
    source: ConnectorState
    policies: list[CompliancePolicyRow] = []
    endpoints_assessed: int = Field(ge=0, default=0)
    note: str = ""


class PostureAssessment(Contract):
    generated_at: datetime
    score: PostureScore
    areas: list[ControlArea]
    gaps: list[PostureGap]
    compliance: ComplianceView
    remediation_trend: list[TrendPoint]
