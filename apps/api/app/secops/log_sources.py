"""Attribution of events that the Wazuh manager receives itself (agent 000): remote syslog and agentless checks.

The organization of such an event is NEVER derived from agent 000, its groups or its name. It comes only from an
explicit, live registration (novrsoc.log_sources) of the event's source, read from the alert's `location`:
  * an IP address            -> a remote syslog sender: wazuh-remoted records the address the datagram or connection
                                came from (the hostname inside the syslog message is chosen by the device and is not
                                used);
  * "(<type>) user@host->..." -> an agentless check: the host configured on the manager;
  * anything else            -> the manager's own logs and modules (file paths, journald, rootcheck...): no tenant.
Unregistered, disabled or archived sources and the manager's own events are quarantined, never assigned by default.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

MANAGER_AGENT_IDS = frozenset({"000"})
_AGENTLESS = re.compile(r"^\(([A-Za-z0-9_]{1,64})\)\s+[^@\s]{1,64}@([A-Za-z0-9][A-Za-z0-9.:-]{0,252})->")
RECEIVING = timedelta(hours=1)
QUIET = timedelta(hours=24)


def classify_location(location: str) -> tuple[str, str]:
    """(kind, value): ('syslog', normalized ip) | ('agentless', lower-case host) | ('manager_local', location)."""
    loc = (location or "").strip()
    try:
        return "syslog", str(ipaddress.ip_address(loc))
    except ValueError:
        pass
    m = _AGENTLESS.match(loc)
    if m:
        return "agentless", m.group(2).lower()
    return "manager_local", loc[:200]


def match_value(kind: str, source_ip: str | None, host: str) -> str:
    return str(ipaddress.ip_address(source_ip)) if kind == "syslog" else host.strip().lower()


def status(*, enabled: bool, retired_at: datetime | None, last_event_at: datetime | None, now: datetime | None = None) -> str:
    if retired_at is not None:
        return "retired"
    if not enabled:
        return "disabled"
    if last_event_at is None:
        return "never_received"
    age = (now or datetime.now(timezone.utc)) - last_event_at
    return "receiving" if age <= RECEIVING else "quiet" if age <= QUIET else "silent"
