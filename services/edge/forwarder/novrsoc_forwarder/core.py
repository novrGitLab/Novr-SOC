"""NovrSOC V2 alert forwarder: Wazuh Indexer -> NovrSOC API (POST /api/v1/soc/ingest/alerts). Forwarding only.

Ported from the legacy forwarder in NovrSOC reconstruction snapshot S2, infra/soar/soar.py lines 472-806
(`search_alerts`, `to_ingest`, `post_batch`, `forward_once`, `late_sweep`, `AgentGroups`, checkpoint v2), see
services/edge/README.md. The algorithm is kept: a deterministic total order (timestamp, Wazuh alert id), a settle
window, a checkpoint that moves only past pages the API acknowledged, a bounded late sweep that never moves the
checkpoint, and partial-shard answers treated as failures. Changed for V2:
  * the V2 contract (contracts v1/soc.AlertIngestBatch): a batch_id per batch and the agent's groups; never an
    organization, severity or status (the API derives the organization from its own group mappings);
  * deterministic batch ids (a hash of the page's sort positions), so a replay after a crash or a lost answer
    carries the same batch_id and the API returns its stored acknowledgement instead of ingesting again;
  * explicit acknowledgement checks: 200, the same batch_id, durable=true and
    accepted + duplicates + quarantined == batch size; anything else does not move the checkpoint;
  * 401/403 (credential revoked or wrong) and 409 (batch_id conflict) stop the service (exit 78, no restart loop);
    422 isolates the invalid alerts by bisection and records them (ids and reason only) in a dead-letter file;
  * a revocable nsk_ machine credential read from a file; TLS always verified; no default URLs;
  * an fsync'd atomic checkpoint and a single-instance lock; JSON logs with secrets redacted and no alert content.
The legacy integratord SOAR engine (process_alert, automatic containment) is NOT part of this service.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .http import Http, HttpError
from .logs import log
from .state import Checkpoint, State

SORT = [{"timestamp": {"order": "asc"}}, {"id": {"order": "asc", "unmapped_type": "keyword", "missing": "_last"}}]
MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")
GROUP = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
AGENT_ID = re.compile(r"^\d{3,6}$")
EXIT_FATAL = 78  # EX_CONFIG: systemd RestartPreventExitStatus=78


class Fatal(Exception):
    """Retrying cannot help (credential refused, batch_id conflict, bad configuration). The service stops."""


class Retryable(Exception):
    """Transient (network, timeout, 429, 5xx, incomplete answer). The checkpoint does not move."""


def parse_ts(ts: str) -> Optional[datetime]:
    """Wazuh writes 2026-10-09T10:00:00.123+0000; fromisoformat wants +00:00."""
    if not ts:
        return None
    t = ts.strip().replace("Z", "+00:00")
    if len(t) >= 5 and t[-5] in "+-" and t[-4:].isdigit():
        t = f"{t[:-2]}:{t[-2:]}"
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def alert_source_id(alert: dict) -> str:
    """Wazuh's own alert id; a hand-made alert without one gets a content hash so ids never collide."""
    if alert.get("id"):
        return str(alert["id"])[:200]
    return "sha1:" + hashlib.sha1(json.dumps(alert, sort_keys=True).encode()).hexdigest()


def valid_sort(value) -> Optional[list]:
    if not isinstance(value, list) or len(value) != 2:
        return None
    ms, alert_id = value
    if isinstance(ms, bool) or not isinstance(ms, (int, float)) or not isinstance(alert_id, str) or not alert_id:
        return None
    return [int(ms), alert_id]


def batch_id_for(positions: List[list]) -> str:
    digest = hashlib.sha256(json.dumps(positions, separators=(",", ":")).encode()).hexdigest()
    return f"fwd-{digest[:48]}"


class Config:
    def __init__(self, env: Dict[str, str]):
        def need(name: str) -> str:
            v = (env.get(name) or "").strip()
            if not v:
                raise Fatal(f"{name} is not set")
            return v

        def number(name: str, default: int, lo: int, hi: int) -> int:
            try:
                return max(lo, min(hi, int(env.get(name) or default)))
            except ValueError:
                raise Fatal(f"{name} must be an integer") from None

        def secret(name: str) -> str:
            path = need(f"{name}_FILE")
            try:
                with open(path, encoding="utf-8") as f:
                    v = f.read().strip()
            except OSError:
                raise Fatal(f"{name}_FILE cannot be read") from None
            if not v:
                raise Fatal(f"{name}_FILE is empty")
            return v

        self.api_url = need("NOVRSOC_API_URL").rstrip("/")
        self.indexer_url = need("WAZUH_INDEXER_URL").rstrip("/")
        self.manager_url = need("WAZUH_API_URL").rstrip("/")
        for name, url in (("NOVRSOC_API_URL", self.api_url), ("WAZUH_INDEXER_URL", self.indexer_url), ("WAZUH_API_URL", self.manager_url)):
            if not url.startswith("https://"):
                raise Fatal(f"{name} must use https")
        self.token = secret("NOVRSOC_FORWARDER_TOKEN")
        if not re.match(r"^nsk_[0-9a-f]{32}\.[A-Za-z0-9_-]{20,}$", self.token):
            raise Fatal("NOVRSOC_FORWARDER_TOKEN_FILE does not hold an nsk_ machine credential")
        self.indexer_user, self.indexer_password = need("WAZUH_INDEXER_USER"), secret("WAZUH_INDEXER_PASSWORD")
        self.manager_user, self.manager_password = need("WAZUH_API_USER"), secret("WAZUH_API_PASSWORD")
        self.api_ca = env.get("NOVRSOC_API_CA_CERT") or None
        self.indexer_ca = env.get("WAZUH_INDEXER_CA_CERT") or None
        self.manager_ca = env.get("WAZUH_API_CA_CERT") or None
        self.alerts_index = env.get("WAZUH_ALERTS_INDEX") or "wazuh-alerts-4.x-*"
        self.state_dir = need("FORWARDER_STATE_DIR")
        self.start_at = need("FORWARDER_START_AT") if not os.path.exists(os.path.join(self.state_dir, "cursor.json")) else None
        self.interval = number("FORWARDER_INTERVAL_SECONDS", 30, 5, 3600)
        self.batch = number("FORWARDER_BATCH", 100, 1, 100)
        self.settle = number("FORWARDER_SETTLE_SECONDS", 60, 0, 3600)
        self.overlap = number("FORWARDER_OVERLAP_SECONDS", 120, 0, 3600)
        self.late_every = number("FORWARDER_LATE_EVERY", 10, 0, 10_000)
        self.late_max_pages = number("FORWARDER_LATE_MAX_PAGES", 5, 1, 50)
        self.max_pages = number("FORWARDER_MAX_PAGES_PER_CYCLE", 50, 1, 500)
        self.min_level = number("FORWARDER_MIN_LEVEL", 0, 0, 16)
        self.timeout = number("FORWARDER_HTTP_TIMEOUT_SECONDS", 30, 2, 300)
        self.group_cache_seconds = number("FORWARDER_GROUP_CACHE_SECONDS", 300, 30, 3600)
        self.group_max_stale_seconds = number("FORWARDER_GROUP_MAX_STALE_SECONDS", 3600, 60, 86400)


class AgentGroups:
    """agent id -> Wazuh groups from the manager's GET /agents (read-only user), refreshed every cache period.
    A failed refresh keeps the previous map until it is older than the max-stale limit; after that the forwarder
    stops sending (Retryable) rather than send groups it cannot vouch for. The API re-checks groups itself when it
    runs in live mode."""

    def __init__(self, http: Http, url: str, user: str, password: str, cache_seconds: int, max_stale: int,
                 clock: Callable[[], float] = time.monotonic):
        self.http, self.url, self.cache_seconds, self.max_stale, self.clock = http, url, cache_seconds, max_stale, clock
        self._basic = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.groups: Dict[str, List[str]] = {}
        self.loaded_at: Optional[float] = None

    def _call(self, method: str, url: str, headers: Dict[str, str]) -> Tuple[int, bytes]:
        try:
            return self.http.request(method, url, headers=headers)
        except HttpError as e:
            raise Retryable(f"manager: {e}") from None

    def _token(self) -> str:
        status, body = self._call("POST", f"{self.url}/security/user/authenticate", {"Authorization": self._basic})
        if status in (401, 403):
            raise Fatal("the Wazuh manager refused WAZUH_API_USER / WAZUH_API_PASSWORD")
        if status != 200:
            raise Retryable(f"Wazuh manager authentication answered {status}")
        try:
            return json.loads(body)["data"]["token"]
        except (ValueError, KeyError, TypeError):
            raise Retryable("Wazuh manager authentication answered unexpectedly") from None

    def refresh(self) -> None:
        token, groups, offset = self._token(), {}, 0
        while True:
            status, body = self._call("GET", f"{self.url}/agents?select=id,group&limit=500&offset={offset}",
                                      {"Authorization": f"Bearer {token}"})
            if status != 200:
                raise Retryable(f"Wazuh agent list answered {status}")
            data = (json.loads(body).get("data") or {})
            items = data.get("affected_items") or []
            for a in items:
                groups[str(a.get("id"))] = [g for g in (a.get("group") or []) if isinstance(g, str) and GROUP.match(g)][:50]
            offset += len(items)
            if not items or offset >= int(data.get("total_affected_items") or 0):
                break
        self.groups, self.loaded_at = groups, self.clock()

    def get(self, agent_id: str) -> List[str]:
        now = self.clock()
        if self.loaded_at is None or now - self.loaded_at > self.cache_seconds:
            try:
                self.refresh()
            except Retryable as e:
                if self.loaded_at is None or now - self.loaded_at > self.max_stale:
                    raise Retryable(f"agent groups unavailable: {e}") from None
                log("warning", "group_cache_stale", age_seconds=int(now - self.loaded_at), reason=str(e))
        return self.groups.get(str(agent_id), [])


def to_ingest(alert: dict, groups: AgentGroups) -> Tuple[Optional[dict], Optional[str]]:
    """The V2 ingest shape (contracts v1/soc.WazuhAlertIn), or (None, reason) when the alert cannot be valid."""
    rule, agent = alert.get("rule") or {}, alert.get("agent") or {}
    ts = parse_ts(str(alert.get("timestamp") or ""))
    if ts is None:
        return None, "timestamp_unparseable"
    try:
        level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        return None, "rule_level_invalid"
    if not 0 <= level <= 16:
        return None, "rule_level_out_of_range"
    agent_id = str(agent.get("id") or "")
    if not AGENT_ID.match(agent_id):
        return None, "agent_id_invalid"
    mitre = (rule.get("mitre") or {}).get("id") or []
    mitre = [str(m) for m in (mitre if isinstance(mitre, list) else [mitre]) if MITRE.match(str(m))][:20]
    data = alert.get("data") or {}
    out = {"id": alert_source_id(alert), "timestamp": ts.isoformat(),
           "rule": {"id": str(rule.get("id", ""))[:20], "level": level, "description": str(rule.get("description") or "")[:1000],
                    "mitre_ids": mitre},
           "agent": {"id": agent_id, "name": str(agent.get("name") or "")[:200], "groups": groups.get(agent_id)},
           "src_ip": str(data.get("srcip"))[:64] if data.get("srcip") else None,
           "raw": alert}
    return out, None


class Forwarder:
    def __init__(self, cfg: Config, *, api: Http, indexer: Http, manager: Http, state: State,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc), sleep: Callable[[float], None] = time.sleep):
        self.cfg, self.api, self.indexer, self.state, self.now, self.sleep = cfg, api, indexer, state, now, sleep
        self._indexer_auth = "Basic " + base64.b64encode(f"{cfg.indexer_user}:{cfg.indexer_password}".encode()).decode()
        self.groups = AgentGroups(manager, cfg.manager_url, cfg.manager_user, cfg.manager_password,
                                  cfg.group_cache_seconds, cfg.group_max_stale_seconds)

    # ---- indexer --------------------------------------------------------------------------------
    def search(self, since: datetime, after: Optional[list], until: datetime, size: int) -> List[dict]:
        rng: Dict[str, Any] = {"gte": since.isoformat(), "lte": until.isoformat()}
        query: Dict[str, Any] = {"bool": {"filter": [{"range": {"timestamp": rng}}]}}
        if self.cfg.min_level > 0:
            query["bool"]["filter"].append({"range": {"rule.level": {"gte": self.cfg.min_level}}})
        body: Dict[str, Any] = {"size": size, "sort": SORT, "query": query}
        if after:
            body["search_after"] = after
        try:
            status, raw = self.indexer.request("POST", f"{self.cfg.indexer_url}/{self.cfg.alerts_index}/_search",
                                               headers={"Authorization": self._indexer_auth}, body=body)
        except HttpError as e:
            raise Retryable(f"indexer: {e}") from None
        if status in (401, 403):
            raise Fatal("the Wazuh indexer refused WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD")
        if status != 200:
            raise Retryable(f"indexer search answered {status}")
        try:
            data = json.loads(raw)
        except ValueError:
            raise Retryable("indexer answered with something other than JSON") from None
        shards = data.get("_shards") or {}
        if data.get("error") is not None or (shards.get("failed") or 0) > 0:
            raise Retryable(f"indexer search incomplete ({shards.get('failed') or 0} shard(s) failed)")
        return (data.get("hits") or {}).get("hits") or []

    # ---- API ------------------------------------------------------------------------------------
    def post(self, batch_id: str, alerts: List[dict]) -> dict:
        body = {"batch_id": batch_id, "alerts": alerts}
        try:
            status, raw = self.api.request("POST", f"{self.cfg.api_url}/api/v1/soc/ingest/alerts",
                                           headers={"Authorization": f"Bearer {self.cfg.token}"}, body=body)
        except HttpError as e:
            raise Retryable(f"api: {e}") from None
        if status == 200:
            try:
                ack = json.loads(raw)
            except ValueError:
                raise Retryable("api acknowledgement is not JSON") from None
            total = sum(int(ack.get(k) or 0) for k in ("accepted", "duplicates", "quarantined"))
            if ack.get("batch_id") != batch_id or ack.get("durable") is not True or total != len(alerts):
                raise Retryable("api acknowledgement does not match the batch; not advancing")
            return ack
        if status in (401, 403):
            raise Fatal(f"the API refused the forwarder credential ({status}); it may be revoked")
        if status == 409:
            raise Fatal("the API reports a batch_id conflict; stop and investigate (state or identity reuse)")
        if status == 422:
            raise ValueError("invalid")
        if status == 429 or status >= 500:
            raise Retryable(f"api answered {status}")
        raise Fatal(f"the API refused the batch ({status})")

    def deliver(self, batch_id: str, alerts: List[dict]) -> Dict[str, int]:
        """Deliver once (retries are the caller's loop). 422: bisect to isolate invalid alerts and dead-letter them."""
        try:
            ack = self.post(batch_id, alerts)
            return {k: int(ack.get(k) or 0) for k in ("accepted", "duplicates", "quarantined")} | {"replayed": int(bool(ack.get("replayed"))), "invalid": 0}
        except ValueError:
            if len(alerts) == 1:
                self.state.dead_letter(alerts[0]["id"], "rejected_by_api_validation", batch_id)
                return {"accepted": 0, "duplicates": 0, "quarantined": 0, "replayed": 0, "invalid": 1}
            mid = len(alerts) // 2
            left = self.deliver(f"{batch_id[:120]}-l", alerts[:mid])
            right = self.deliver(f"{batch_id[:120]}-r", alerts[mid:])
            return {k: left[k] + right[k] for k in left}

    def send_page(self, hits: List[dict]) -> Dict[str, int]:
        positions = [valid_sort(h.get("sort")) for h in hits]
        alerts, counts = [], {"accepted": 0, "duplicates": 0, "quarantined": 0, "replayed": 0, "invalid": 0}
        for h in hits:
            out, reason = to_ingest(h.get("_source") or {}, self.groups)
            if out is None:
                self.state.dead_letter(alert_source_id(h.get("_source") or {}), reason or "invalid", None)
                counts["invalid"] += 1
            else:
                alerts.append(out)
        if alerts:
            got = self.deliver(batch_id_for([p for p in positions if p]), alerts)
            counts = {k: counts[k] + got[k] for k in counts}
        return counts

    # ---- one cycle (port of forward_once) ----------------------------------------------------------
    def forward_once(self, cycle: int = 0) -> int:
        try:
            cp = self.state.load()
        except (OSError, ValueError):
            # Unlike the legacy forwarder, an unreadable checkpoint is never treated as a first run (that could
            # skip or replay a window silently): stop and let an operator restore it (README, recovery).
            raise Fatal("cursor.json is unreadable; restore it from backup or follow the recovery procedure") from None
        now = self.now()
        until = now - timedelta(seconds=self.cfg.settle)
        if cp is None:
            start = self.cfg.start_at
            since = now if start in (None, "now") else parse_ts(start)
            if since is None:
                raise Fatal("FORWARDER_START_AT must be 'now' or an ISO timestamp")
            after = None
            log("info", "first_run", since=since.isoformat())
            cp = Checkpoint(since, None)
            self.state.save(cp)
        else:
            since, after = (cp.ts, cp.sort) if cp.sort else (cp.ts - timedelta(seconds=self.cfg.overlap), None)
        sent = 0
        for _ in range(self.cfg.max_pages):
            hits = self.search(since, after, until, self.cfg.batch)
            if not hits:
                break
            position = next((s for s in (valid_sort(h.get("sort")) for h in reversed(hits)) if s), None)
            if position is None:
                raise Retryable("indexer returned a page without sort values; not advancing")
            counts = self.send_page(hits)
            sent += len(hits)
            cp = Checkpoint(datetime.fromtimestamp(position[0] / 1000, tz=timezone.utc), position)
            self.state.save(cp)
            log("info", "page_acknowledged", alerts=len(hits), position_ms=position[0], **counts)
            after = position
            if len(hits) < self.cfg.batch:
                break
        if cp.sort and self.cfg.late_every and cycle % self.cfg.late_every == 0:
            self.late_sweep(cp)
        return sent

    def late_sweep(self, cp: Checkpoint) -> int:
        """Re-send the overlap window behind the checkpoint (bounded; never moves the checkpoint)."""
        since, after, sent = cp.ts - timedelta(seconds=self.cfg.overlap), None, 0
        for _ in range(self.cfg.late_max_pages):
            hits = self.search(since, after, cp.ts, self.cfg.batch)
            if not hits:
                return sent
            counts = self.send_page(hits)
            sent += len(hits)
            if counts["accepted"]:
                log("info", "late_alerts_found", accepted=counts["accepted"])
            after = valid_sort(hits[-1].get("sort"))
            if len(hits) < self.cfg.batch or after is None:
                return sent
        log("warning", "late_sweep_bounded", max_pages=self.cfg.late_max_pages)
        return sent

    # ---- service loop ---------------------------------------------------------------------------
    def run(self, stop: Callable[[], bool] = lambda: False, max_cycles: Optional[int] = None) -> int:
        cycle, failures = 0, 0
        log("info", "started", api=self.cfg.api_url, indexer=self.cfg.indexer_url, interval=self.cfg.interval)
        while not stop() and (max_cycles is None or cycle < max_cycles):
            cycle += 1
            try:
                self.forward_once(cycle)
                failures = 0
                delay = float(self.cfg.interval)
            except Retryable as e:
                failures += 1
                delay = min(300.0, 2.0 ** min(failures, 8)) * (0.5 + random.random() / 2)
                log("warning", "cycle_retry", reason=str(e), failures=failures, retry_in_seconds=round(delay, 1))
            except Fatal as e:
                log("error", "stopped", reason=str(e))
                return EXIT_FATAL
            if not stop():
                self.sleep(delay)
        log("info", "stopping")
        return 0
