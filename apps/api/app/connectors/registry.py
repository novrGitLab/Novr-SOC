"""Which connector implementation the API uses, and the honest state it reports.

NOVRSOC_WAZUH_MODE:
  unconfigured   (default) no Wazuh data; every Wazuh-backed response says `unconfigured`
  local_fixture  the labelled local fixture (development/test only; refused elsewhere by Settings)
  live           Phase 5: the TLS-verified, read-only clients in wazuh_live.py, configured from WAZUH_* and
                 WAZUH_INDEXER_* environment variables. The state is `connected` ONLY after a health check
                 against the real service succeeded within the last HEALTH_TTL seconds; otherwise `unavailable`
                 (unreachable, timeout, TLS failure), `error` (credentials refused, unexpected answer) or
                 `unconfigured` (missing settings, named).
Ollama: no inference connector is mounted in the API process; NHAI inference runs in the NHAI worker
(app/nhai/worker.py), whose backend is reported by nhai_state().
"""
from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone

from app.connectors.base import ConnectorError, ConnectorRejected, ConnectorUnconfigured
from app.connectors.wazuh_fixture import FixtureWazuh
from app.connectors.wazuh_live import LiveWazuh, build_live
from app.core.config import Settings
from app.core.tls import TlsConfigError
from novrsoc_contracts.v1.endpoints import ConnectorState

HEALTH_TTL = 60.0
_WAZUH_DETAIL = {
    "unconfigured": "No NovrSIEM connection is configured for this installation.",
    "local_fixture": "Local fixture data for development and tests. Not live telemetry.",
}

_lock = threading.Lock()
_live: LiveWazuh | None = None
_live_error: str | None = None
_health: dict[str, tuple[float, ConnectorState]] = {}
# Tests replace this to inject fake transports; production builds from the process environment.
live_factory: Callable[[Mapping[str, str], str], LiveWazuh] = build_live
clock: Callable[[], float] = time.monotonic


def reset() -> None:
    """Forget the cached live client and health results (tests; configuration change)."""
    global _live, _live_error
    with _lock:
        _live, _live_error = None, None
        _health.clear()


def _get_live(settings: Settings) -> LiveWazuh | None:
    global _live, _live_error
    with _lock:
        if _live is None and _live_error is None:
            try:
                _live = live_factory(os.environ, settings.env)
            except (ConnectorUnconfigured, TlsConfigError, KeyError) as e:
                _live_error = str(e) if not isinstance(e, KeyError) else f"missing setting {e}"
        return _live


def wazuh(settings: Settings) -> FixtureWazuh | LiveWazuh | None:
    if settings.wazuh_mode == "local_fixture":
        return FixtureWazuh()
    if settings.wazuh_mode == "live":
        return _get_live(settings)
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _checked(name: str, connector: str, check: Callable[[], object]) -> ConnectorState:
    hit = _health.get(name)
    if hit and clock() - hit[0] < HEALTH_TTL:
        return hit[1]
    try:
        check()
        state = ConnectorState(connector=connector, state="connected", detail="Live: the service answered the last health check.",
                               checked_at=_now())
    except ConnectorRejected as e:
        state = ConnectorState(connector=connector, state="error", detail=str(e)[:300], checked_at=_now())
    except ConnectorError as e:
        state = ConnectorState(connector=connector, state="unavailable", detail=str(e)[:300], checked_at=_now())
    _health[name] = (clock(), state)
    return state


def wazuh_states(settings: Settings) -> list[ConnectorState]:
    if settings.wazuh_mode != "live":
        state = "local_fixture" if settings.wazuh_mode == "local_fixture" else "unconfigured"
        return [ConnectorState(connector="wazuh_manager", state=state, detail=_WAZUH_DETAIL[state]),
                ConnectorState(connector="wazuh_indexer", state=state, detail=_WAZUH_DETAIL[state])]
    live = _get_live(settings)
    if live is None:
        detail = f"Live mode is selected but not configured: {_live_error}"[:300]
        return [ConnectorState(connector="wazuh_manager", state="unconfigured", detail=detail),
                ConnectorState(connector="wazuh_indexer", state="unconfigured", detail=detail)]
    manager = _checked("manager", "wazuh_manager", live.manager.health)
    indexer = (_checked("indexer", "wazuh_indexer", live.indexer.health) if live.indexer is not None else
               ConnectorState(connector="wazuh_indexer", state="unconfigured",
                              detail="The NovrSIEM event store is not configured: vulnerability counts and alert evidence are unavailable."))
    return [manager, indexer]


def ollama_state() -> ConnectorState:
    """The API process never calls Ollama. Inference state is reported per NHAI job and by the NHAI worker."""
    return ConnectorState(connector="ollama", state="unconfigured",
                          detail="NHAI analyses run through the NHAI interface, outside the API; see NHAI status.")


# ---------------------------------------------------------------- server-controlled agent enrollment (write-capable)
from app.connectors.enrollment import ManagerEnrollment, enrollment_from_env  # noqa: E402

enrollment_factory: Callable[[Mapping[str, str], str], ManagerEnrollment] = enrollment_from_env
_enrollment: ManagerEnrollment | None = None
_enrollment_error: str | None = None
_version: tuple[float, str | None, str] | None = None
VERSION_TTL = 300.0


def enrollment(settings: Settings) -> ManagerEnrollment | None:
    """The enrollment client, or None when enrollment is disabled or not configured (see enrollment_problem)."""
    global _enrollment, _enrollment_error
    if settings.enrollment_mode != "manager_api":
        return None
    with _lock:
        if _enrollment is None and _enrollment_error is None:
            try:
                _enrollment = enrollment_factory(os.environ, settings.env)
            except (ConnectorUnconfigured, TlsConfigError, KeyError) as e:
                _enrollment_error = str(e) if not isinstance(e, KeyError) else f"missing setting {e}"
        return _enrollment


def enrollment_problem(settings: Settings) -> str | None:
    if settings.enrollment_mode != "manager_api":
        return "Agent enrollment is not enabled in this installation."
    if enrollment(settings) is None:
        return "Agent enrollment is not configured in this installation."
    return None


def manager_version(settings: Settings) -> tuple[str | None, str]:
    """(version, detail) of the NovrSIEM manager as it reports itself, cached for VERSION_TTL seconds."""
    global _version
    client = enrollment(settings)
    if client is None:
        return None, enrollment_problem(settings) or "unknown"
    with _lock:
        if _version is not None and clock() - _version[0] < VERSION_TTL:
            return _version[1], _version[2]
    try:
        v, detail = client.version(), "reported by the manager"
    except ConnectorError as e:
        v, detail = None, f"The NovrSIEM manager version could not be read: {e}"[:300]
    with _lock:
        _version = (clock(), v, detail)
    return v, detail


def reset_enrollment() -> None:
    """Forget the enrollment client and cached version (tests and configuration changes)."""
    global _enrollment, _enrollment_error, _version
    with _lock:
        _enrollment, _enrollment_error, _version = None, None, None
