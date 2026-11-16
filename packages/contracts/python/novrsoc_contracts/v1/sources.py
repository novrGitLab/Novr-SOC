"""Syslog and agentless sources (organization management): devices that reach NovrSOC through the Wazuh manager.

Wazuh records events it receives itself under agent 000. Their organization is never derived from agent 000 or from
a group; it comes only from an explicit registration:
  syslog     the sender address wazuh-remoted records in the alert's `location` (the address the datagram or
             connection came from, not the hostname written inside the syslog message, which the device controls);
  agentless  the host configured in the manager's <agentless> block (`location` "(<type>) user@host->...").
A match value is registered to one organization at a time, across ALL organizations. An event from an unregistered,
disabled or archived source, and the manager's own local events, are quarantined; nothing is attributed by default.
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .common import Contract

SourceKind = Literal["syslog", "agentless"]
DeviceType = Literal["firewall", "router", "switch", "linux_server", "windows_server", "network_appliance", "storage", "other"]
SourceProtocol = Literal["udp", "tcp", "tls", "ssh"]
SourceStatus = Literal["receiving", "quiet", "silent", "never_received", "disabled", "retired"]
HostName = Annotated[str, Field(max_length=253, pattern=r"^$|^[A-Za-z0-9]([A-Za-z0-9.:-]{0,252})$")]


def _check_ip(v: str | None) -> None:
    if v is not None:
        ipaddress.ip_address(v)


def _check_net(v: str | None) -> None:
    if v is not None:
        ipaddress.ip_network(v, strict=True)


class LogSourceCreate(Contract):
    name: Annotated[str, Field(min_length=2, max_length=120)]
    kind: SourceKind = "syslog"
    source_ip: Annotated[str, Field(max_length=45)] | None = Field(default=None, description="syslog: the sender address")
    host: HostName = Field(default="", description="agentless: the host as configured on the Wazuh manager")
    device_type: DeviceType
    vendor: Annotated[str, Field(max_length=120)] = ""
    protocol: SourceProtocol = "udp"
    port: Annotated[int, Field(ge=1, le=65535)] | None = None
    site_id: uuid.UUID | None = None
    network: Annotated[str, Field(max_length=49)] | None = Field(default=None, description="CIDR the source sits in")
    authorization_reference: Annotated[str, Field(min_length=3, max_length=200)] = Field(
        description="The client authorization (ticket, contract clause) for collecting this device's logs")
    notes: Annotated[str, Field(max_length=2000)] = ""
    enabled: bool = True

    @model_validator(mode="after")
    def _shape(self) -> "LogSourceCreate":
        _check_ip(self.source_ip)
        _check_net(self.network)
        if self.kind == "syslog":
            if not self.source_ip:
                raise ValueError("a syslog source needs its source_ip")
            if self.protocol not in ("udp", "tcp", "tls"):
                raise ValueError("a syslog source uses udp, tcp or tls")
        else:
            if not self.host:
                raise ValueError("an agentless source needs its host")
            if self.protocol != "ssh":
                raise ValueError("an agentless source uses ssh")
        if self.network and self.source_ip and ipaddress.ip_address(self.source_ip) not in ipaddress.ip_network(self.network):
            raise ValueError("source_ip is not inside network")
        return self


class LogSourceUpdate(Contract):
    """A field left out (null) is unchanged. Changing source_ip or host changes what the source matches."""
    name: Annotated[str, Field(min_length=2, max_length=120)] | None = None
    source_ip: Annotated[str, Field(max_length=45)] | None = None
    host: HostName | None = None
    device_type: DeviceType | None = None
    vendor: Annotated[str, Field(max_length=120)] | None = None
    protocol: SourceProtocol | None = None
    port: Annotated[int, Field(ge=1, le=65535)] | None = None
    site_id: uuid.UUID | None = None
    clear_site: bool = False
    network: Annotated[str, Field(max_length=49)] | None = None
    clear_network: bool = False
    authorization_reference: Annotated[str, Field(min_length=3, max_length=200)] | None = None
    notes: Annotated[str, Field(max_length=2000)] | None = None
    enabled: bool | None = None

    @model_validator(mode="after")
    def _shape(self) -> "LogSourceUpdate":
        _check_ip(self.source_ip)
        _check_net(self.network)
        return self


class LogSourceReassign(Contract):
    org_id: uuid.UUID = Field(description="The organization that now owns the device")
    reason: Annotated[str, Field(min_length=5, max_length=500)]


class LogSourceRetire(Contract):
    reason: Annotated[str, Field(min_length=5, max_length=500)]


class LogSourceView(Contract):
    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    kind: SourceKind
    source_ip: str | None
    host: str
    match_value: str
    device_type: DeviceType
    vendor: str
    protocol: SourceProtocol
    port: int | None
    site_id: uuid.UUID | None
    site_name: str | None = None
    network: str | None
    enabled: bool
    authorization_reference: str
    notes: str
    asset_id: uuid.UUID | None
    event_count: int = Field(ge=0)
    last_event_at: datetime | None
    status: SourceStatus = Field(description="receiving: an event in the last hour; quiet: in the last 24 hours; silent: none for "
                                 "24 hours or more; never_received; disabled; retired (reassigned or removed, kept for history)")
    retired_at: datetime | None = None
    retired_reason: str = ""
    created_at: datetime
    updated_at: datetime


class LogSourceList(Contract):
    items: list[LogSourceView]
