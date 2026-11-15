"""Organization-specific Threat Insights and collector telemetry connector interfaces.

Threat Insights (workstream F): indicators come from vetted sources; matching runs ONLY against the
calling organization's own evidence (OrgScope); no indicator match or evidence crosses organizations.

Collector telemetry (workstream C): the sink receives a batch together with the AUTHENTICATED service
identity. Organization and site are taken from the identity. attribute_events() decides, per event,
whether it can be attributed to that site or must be quarantined.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.auth.deps import ServicePrincipal
from app.connectors.base import ConnectorHealth, OrgScope, ip_in_networks
from novrsoc_contracts.v1.collector import TelemetryAck, TelemetryBatch, TelemetryEvent
from novrsoc_contracts.v1.insights import Indicator, InsightMatch


class IndicatorSource(Protocol):
    name: str
    def fetch(self, since: datetime) -> list[Indicator]: ...
    def health(self) -> ConnectorHealth: ...


class InsightMatcher(Protocol):
    def match(self, scope: OrgScope, observables: Sequence[str]) -> list[InsightMatch]: ...


class TelemetrySink(Protocol):
    def accept(self, identity: ServicePrincipal, batch: TelemetryBatch) -> TelemetryAck: ...


@dataclass(frozen=True)
class Attribution:
    accepted: tuple[TelemetryEvent, ...]
    quarantined: tuple[tuple[TelemetryEvent, str], ...]


def attribute_events(identity: ServicePrincipal, site_networks: Sequence[str], batch: TelemetryBatch) -> Attribution:
    """An event is attributable only if its sender is at the identity's own site AND inside that site's
    declared networks. Anything else is quarantined with a reason (never dropped silently, never
    attributed to another site or organization)."""
    if identity.kind != "collector" or identity.site_id is None:
        raise PermissionError("only a site-bound collector identity may submit telemetry")
    ok: list[TelemetryEvent] = []
    bad: list[tuple[TelemetryEvent, str]] = []
    for e in batch.events:
        if e.sender.site_id != identity.site_id:
            bad.append((e, "sender_site_mismatch"))
        elif not site_networks or not ip_in_networks(e.sender.ip, site_networks):
            bad.append((e, "sender_outside_site_networks"))
        else:
            ok.append(e)
    return Attribution(tuple(ok), tuple(bad))
