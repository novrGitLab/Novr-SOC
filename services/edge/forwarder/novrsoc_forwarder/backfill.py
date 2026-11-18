"""Historical alert backfill: the Wazuh Indexer window [start, end) -> the NovrSOC API, SEPARATE from the live forwarder.

  python -m novrsoc_forwarder.backfill plan   --start ISO --end ISO --plan FILE [--report FILE] [--org SLUG ...]
                                              [--limit N] [--include-quarantine] [--live-start ISO]
  python -m novrsoc_forwarder.backfill import --plan FILE --approve PLAN_SHA256 [--batches-per-minute N]
  python -m novrsoc_forwarder.backfill status

plan    READ-ONLY. Reads the window from the indexer in the live forwarder's deterministic order (timestamp, Wazuh alert
        id) and asks the API what ingest WOULD do with every alert (POST /api/v1/soc/ingest/classify: the same
        ownership decision as ingest, nothing stored). Writes a plan (pages, their positions and an ownership digest
        per page, the eligible count) and a classification report. Nothing is imported.
import  Requires the plan's sha256 as --approve (the explicit operational approval of exactly that plan). Re-reads each
        page, re-classifies it and stops if its ownership digest changed (mappings, agent groups, source registrations
        or index content changed since the plan: re-plan). Sends only the eligible alerts through the existing ingest
        contract (POST /api/v1/soc/ingest/alerts) in deterministic batches ("bkf-" + hash of the plan and the page), so
        a retry after a crash or a lost answer replays the API's stored receipt. Database deduplication (organization,
        source, Wazuh alert id) makes an alert the live forwarder already delivered a duplicate, never a copy.
        The page checkpoint moves only after the API acknowledged the batch; an interrupted import resumes there.

Safety: its OWN state directory (BACKFILL_STATE_DIR: backfill-state.json, backfill.lock, backfill-ledger.jsonl (alert ids
per acknowledged batch, for audit and rollback: `python -m app.cli backfill-rollback` on Server 2), backfill-dead-letters.jsonl),
which must not be the live forwarder's (cursor.json / forwarder.lock are refused), its own machine credential
(NOVRSOC_BACKFILL_TOKEN_FILE: a separate forwarder identity, revocable on its own), a paced request rate, bounded
retries, and the window must end before the live forwarder's start (--live-start) and before now minus the settle time.
Unattributable alerts are NOT sent unless --include-quarantine (they would only fill the quarantine). Logs carry ids,
counts and positions only, with credentials redacted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

from .core import SORT, AgentGroups, Fatal, Retryable, alert_source_id, parse_ts, to_ingest, valid_sort
from .http import Http, HttpError
from .logs import log

EXIT_FATAL, EXIT_RETRY, EXIT_STALE = 78, 75, 65
PLAN_KIND, PLAN_VERSION = "novrsoc-backfill-plan", 1
FORWARDER_FILES = ("cursor.json", "forwarder.lock")


class Stale(Exception):
    """The window no longer classifies as planned: re-plan before importing (nothing of this page was sent)."""


def _secret(env: Dict[str, str], name: str) -> str:
    path = (env.get(f"{name}_FILE") or "").strip()
    if not path:
        raise Fatal(f"{name}_FILE is not set")
    try:
        with open(path, encoding="utf-8") as f:
            v = f.read().strip()
    except OSError:
        raise Fatal(f"{name}_FILE cannot be read") from None
    if not v:
        raise Fatal(f"{name}_FILE is empty")
    return v


class BackfillConfig:
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

        self.api_url = need("NOVRSOC_API_URL").rstrip("/")
        self.indexer_url = need("WAZUH_INDEXER_URL").rstrip("/")
        self.manager_url = need("WAZUH_API_URL").rstrip("/")
        for name, url in (("NOVRSOC_API_URL", self.api_url), ("WAZUH_INDEXER_URL", self.indexer_url), ("WAZUH_API_URL", self.manager_url)):
            if not url.startswith("https://"):
                raise Fatal(f"{name} must use https")
        self.token = _secret(env, "NOVRSOC_BACKFILL_TOKEN")
        if not self.token.startswith("nsk_"):
            raise Fatal("NOVRSOC_BACKFILL_TOKEN_FILE does not hold an nsk_ machine credential")
        self.indexer_user, self.indexer_password = need("WAZUH_INDEXER_USER"), _secret(env, "WAZUH_INDEXER_PASSWORD")
        self.manager_user, self.manager_password = need("WAZUH_API_USER"), _secret(env, "WAZUH_API_PASSWORD")
        self.api_ca = env.get("NOVRSOC_API_CA_CERT") or None
        self.indexer_ca = env.get("WAZUH_INDEXER_CA_CERT") or None
        self.manager_ca = env.get("WAZUH_API_CA_CERT") or None
        self.alerts_index = env.get("WAZUH_ALERTS_INDEX") or "wazuh-alerts-4.x-*"
        self.state_dir = need("BACKFILL_STATE_DIR")
        self.forwarder_state_dir = (env.get("FORWARDER_STATE_DIR") or "").strip() or None
        self.page = number("BACKFILL_PAGE_SIZE", 100, 1, 100)
        self.min_level = number("BACKFILL_MIN_LEVEL", 0, 0, 16)
        self.timeout = number("BACKFILL_HTTP_TIMEOUT_SECONDS", 60, 5, 300)
        self.settle = number("BACKFILL_SETTLE_SECONDS", 300, 0, 86400)
        self.max_retries = number("BACKFILL_MAX_RETRIES", 6, 0, 20)


class BackfillState:
    """backfill-state.json: {"plan_sha256", "next_page", "counts"}; atomic and fsync'd. Never the forwarder's files."""

    def __init__(self, directory: str, forwarder_dir: Optional[str]):
        real = os.path.realpath(directory)
        if forwarder_dir and real == os.path.realpath(forwarder_dir):
            raise Fatal("BACKFILL_STATE_DIR is the live forwarder's state directory: use a separate directory")
        if os.path.isdir(real) and any(os.path.exists(os.path.join(real, f)) for f in FORWARDER_FILES):
            raise Fatal("BACKFILL_STATE_DIR holds live forwarder state (cursor.json / forwarder.lock): use a separate directory")
        os.makedirs(real, mode=0o700, exist_ok=True)
        self.dir = real
        self.path = os.path.join(real, "backfill-state.json")
        self.dead = os.path.join(real, "backfill-dead-letters.jsonl")
        self.ledger_path = os.path.join(real, "backfill-ledger.jsonl")
        self._lock = None

    def lock(self) -> None:
        fh = open(os.path.join(self.dir, "backfill.lock"), "a+")
        try:
            try:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except ImportError:  # Windows (development only)
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            fh.close()
            raise Fatal("another backfill holds the state directory lock") from None
        self._lock = fh

    def unlock(self) -> None:
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def load(self) -> Optional[dict]:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            raise Fatal("backfill-state.json is unreadable; restore it or start a new state directory") from None
        if not isinstance(data, dict) or not isinstance(data.get("next_page"), int):
            raise Fatal("backfill-state.json has no usable position")
        return data

    def save(self, data: dict) -> None:
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({**data, "saved_at": datetime.now(timezone.utc).isoformat()}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def ledger(self, entry: dict) -> None:
        """Ids only, never content. Before a batch is sent: {"intent", ids, new_ids} where new_ids are the alerts the API
        classified as NOT yet stored just before sending (only those can be inserted by this import, so only those are
        ever rolled back); after its acknowledgement: {"ack"}. Written before sending, so an interrupted batch is listed."""
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"at": datetime.now(timezone.utc).isoformat(), **entry}) + chr(10))
            f.flush()
            os.fsync(f.fileno())

    def dead_letter(self, alert_id: str, reason: str, batch_id: Optional[str]) -> None:
        with open(self.dead, "a", encoding="utf-8") as f:
            f.write(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "alert_id": str(alert_id)[:200],
                                "reason": reason, "batch_id": batch_id}) + "\n")
            f.flush()
            os.fsync(f.fileno())


def plan_hash(plan: dict) -> str:
    body = {k: v for k, v in plan.items() if k != "plan_sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def owner_digest(items: List[Tuple[str, str]]) -> str:
    """Ownership of a page: (alert id, organization id or 'quarantine:<reason>' or 'invalid:<reason>'). Whether an
    alert is new or already stored is NOT part of it, so a resumed import is not mistaken for a changed one."""
    return hashlib.sha256(json.dumps(items, separators=(",", ":")).encode()).hexdigest()


class Backfill:
    def __init__(self, cfg: BackfillConfig, *, api: Http, indexer: Http, manager: Http, state: BackfillState,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc), sleep: Callable[[float], None] = time.sleep):
        import base64
        self.cfg, self.api, self.indexer, self.state, self.now, self.sleep = cfg, api, indexer, state, now, sleep
        self._indexer_auth = "Basic " + base64.b64encode(f"{cfg.indexer_user}:{cfg.indexer_password}".encode()).decode()
        self.groups = AgentGroups(manager, cfg.manager_url, cfg.manager_user, cfg.manager_password, 300, 3600)
        self.failed = 0   # operations that exhausted their retries in this run (the page is retried on resume)

    # ---- reads --------------------------------------------------------------------------------------------------
    def search(self, start: datetime, end: datetime, after: Optional[list], size: int) -> List[dict]:
        query: dict = {"bool": {"filter": [{"range": {"timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}}]}}
        if self.cfg.min_level > 0:
            query["bool"]["filter"].append({"range": {"rule.level": {"gte": self.cfg.min_level}}})
        body: dict = {"size": size, "sort": SORT, "query": query}
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
        if data.get("error") is not None or ((data.get("_shards") or {}).get("failed") or 0) > 0:
            raise Retryable("indexer search incomplete (failed shards)")
        hits = (data.get("hits") or {}).get("hits") or []
        if any(valid_sort(h.get("sort")) is None for h in hits):
            raise Retryable("indexer returned hits without sort values")
        return hits

    def _post(self, path: str, body: dict) -> Tuple[int, bytes]:
        try:
            return self.api.request("POST", f"{self.cfg.api_url}{path}", headers={"Authorization": f"Bearer {self.cfg.token}"}, body=body)
        except HttpError as e:
            raise Retryable(f"api: {e}") from None

    def classify(self, alerts: List[dict]) -> List[dict]:
        """The API's verdict for each alert, in order. A 422 is isolated by bisection (the alert is then 'invalid')."""
        if not alerts:
            return []
        status, raw = self._post("/api/v1/soc/ingest/classify", {"alerts": alerts})
        if status == 200:
            items = json.loads(raw).get("items") or []
            if [i.get("id") for i in items] != [a["id"] for a in alerts]:
                raise Retryable("classification answer does not match the request")
            return items
        if status == 422:
            if len(alerts) == 1:
                return [{"id": alerts[0]["id"], "verdict": "invalid", "reason": "rejected_by_api_validation"}]
            mid = len(alerts) // 2
            return self.classify(alerts[:mid]) + self.classify(alerts[mid:])
        if status == 404:
            raise Fatal("the API has no /api/v1/soc/ingest/classify: Server 2 must run a release with historical backfill support")
        if status in (401, 403):
            raise Fatal(f"the API refused the backfill credential ({status})")
        if status == 429 or status >= 500:
            raise Retryable(f"api answered {status}")
        raise Fatal(f"the API refused the classification ({status})")

    def classified_page(self, hits: List[dict]) -> List[dict]:
        """One record per hit, in index order: {id, alert (ingest shape) or None, verdict, org_id, org_slug, reason}."""
        rows, valid = [], []
        for h in hits:
            out, reason = to_ingest(h.get("_source") or {}, self.groups)
            if out is None:
                rows.append({"id": alert_source_id(h.get("_source") or {}), "alert": None, "verdict": "invalid", "reason": reason,
                             "agent": str(((h.get("_source") or {}).get("agent") or {}).get("id") or "")})
            else:
                rows.append({"id": out["id"], "alert": out, "agent": out["agent"]["id"]})
                valid.append(out)
        by_id = {}
        for v in self.classify(valid):
            by_id[v["id"]] = v
        for r in rows:
            if r["alert"] is not None:
                r.update({k: by_id[r["id"]].get(k) for k in ("verdict", "org_id", "org_slug", "reason", "log_source_id")})
        return rows

    @staticmethod
    def owner(r: dict) -> str:
        if r["verdict"] in ("new", "duplicate"):
            return str(r["org_id"])
        return f"{r['verdict']}:{r.get('reason') or ''}"

    @staticmethod
    def eligible(r: dict, orgs: Optional[List[str]], include_quarantine: bool) -> bool:
        if r["verdict"] in ("new", "duplicate"):
            return not orgs or r.get("org_slug") in orgs
        return include_quarantine and r["verdict"] == "quarantine"

    # ---- plan (read-only) ---------------------------------------------------------------------------------------
    def plan(self, start: datetime, end: datetime, *, orgs: Optional[List[str]] = None, limit: Optional[int] = None,
             include_quarantine: bool = False, pace: float = 0.0) -> Tuple[dict, dict]:
        pages, after, totals = [], None, Counter()
        by_org: Dict[str, Counter] = {}
        by_reason, q_agents, q_sources, invalid_ids = Counter(), Counter(), Counter(), []
        taken = 0
        while True:
            hits = self.search(start, end, after, self.cfg.page)
            if not hits:
                break
            rows = self.classified_page(hits)
            last = valid_sort(hits[-1]["sort"])
            elig = [r for r in rows if self.eligible(r, orgs, include_quarantine)]
            if limit is not None:
                elig = elig[:max(0, limit - taken)]
            taken += len(elig)
            pages.append({"after": after, "last": last, "count": len(hits), "eligible": len(elig),
                          "digest": owner_digest([(r["id"], self.owner(r)) for r in rows])})
            for r in rows:
                totals["scanned"] += 1
                totals[r["verdict"]] += 1
                if r["verdict"] in ("new", "duplicate"):
                    by_org.setdefault(r.get("org_slug") or str(r["org_id"]), Counter())[r["verdict"]] += 1
                elif r["verdict"] == "quarantine":
                    by_reason[r.get("reason") or "unknown"] += 1
                    if r["agent"] == "000":
                        q_sources[str(((r["alert"] or {}).get("raw") or {}).get("location") or "")[:120]] += 1
                    else:
                        q_agents[r["agent"]] += 1
                else:
                    by_reason[f"invalid:{r.get('reason')}"] += 1
                    if len(invalid_ids) < 100:
                        invalid_ids.append(r["id"])
            totals["eligible"] += len(elig)
            after = last
            log("info", "plan_page", page=len(pages), scanned=totals["scanned"], eligible=totals["eligible"], position_ms=last[0])
            if (limit is not None and taken >= limit) or len(hits) < self.cfg.page:
                break
            if pace:
                self.sleep(pace)
        plan = {"kind": PLAN_KIND, "version": PLAN_VERSION, "created_at": self.now().isoformat(),
                "window": {"start": start.isoformat(), "end": end.isoformat()}, "index": self.cfg.alerts_index,
                "min_level": self.cfg.min_level, "page_size": self.cfg.page, "api_url": self.cfg.api_url,
                "filters": {"orgs": sorted(orgs) if orgs else [], "include_quarantine": include_quarantine}, "limit": limit,
                "totals": dict(totals), "pages": pages}
        plan["plan_sha256"] = plan_hash(plan)
        report = {"plan_sha256": plan["plan_sha256"], "window": plan["window"], "filters": plan["filters"], "limit": limit,
                  "counts": {k: totals.get(k, 0) for k in ("scanned", "eligible", "new", "duplicate", "quarantine", "invalid")},
                  "by_organization": {k: dict(v) for k, v in sorted(by_org.items())},
                  "quarantine_by_reason": dict(by_reason), "quarantined_agents_top": q_agents.most_common(25),
                  "unattributed_sources_top": q_sources.most_common(25), "invalid_ids_sample": invalid_ids,
                  "note": "Read-only classification: nothing was imported. Agent groups are the Wazuh manager's CURRENT ones."}
        return plan, report

    # ---- import -------------------------------------------------------------------------------------------------
    def deliver(self, batch_id: str, alerts: List[dict]) -> Dict[str, int]:
        status, raw = self._post("/api/v1/soc/ingest/alerts", {"batch_id": batch_id, "alerts": alerts})
        if status == 200:
            ack = json.loads(raw)
            total = sum(int(ack.get(k) or 0) for k in ("accepted", "duplicates", "quarantined"))
            if ack.get("batch_id") != batch_id or ack.get("durable") is not True or total != len(alerts):
                raise Retryable("api acknowledgement does not match the batch; not advancing")
            replayed = bool(ack.get("replayed"))
            return {"accepted": 0 if replayed else int(ack["accepted"]), "duplicates": 0 if replayed else int(ack["duplicates"]),
                    "quarantined": 0 if replayed else int(ack["quarantined"]), "replayed": len(alerts) if replayed else 0, "invalid": 0}
        if status == 422:
            if len(alerts) == 1:
                self.state.dead_letter(alerts[0]["id"], "rejected_by_api_validation", batch_id)
                return {"accepted": 0, "duplicates": 0, "quarantined": 0, "replayed": 0, "invalid": 1}
            mid = len(alerts) // 2
            left = self.deliver(f"{batch_id[:120]}-l", alerts[:mid])
            right = self.deliver(f"{batch_id[:120]}-r", alerts[mid:])
            return {k: left[k] + right[k] for k in left}
        if status in (401, 403):
            raise Fatal(f"the API refused the backfill credential ({status}); it may be revoked")
        if status == 409:
            raise Fatal("the API reports a batch_id conflict (state or identity reuse); stop and investigate")
        if status == 429 or status >= 500:
            raise Retryable(f"api answered {status}")
        raise Fatal(f"the API refused the batch ({status})")

    def run_import(self, plan: dict, approve: str, *, batches_per_minute: int = 30) -> Dict[str, int]:
        if plan.get("kind") != PLAN_KIND or plan.get("version") != PLAN_VERSION:
            raise Fatal("not a backfill plan")
        sha = plan_hash(plan)
        if plan.get("plan_sha256") != sha:
            raise Fatal("the plan file was modified after it was written")
        if approve != sha:
            raise Fatal("--approve does not match this plan's sha256: review the classification report and approve it explicitly")
        if plan["api_url"] != self.cfg.api_url or plan["index"] != self.cfg.alerts_index or plan["page_size"] != self.cfg.page \
                or plan["min_level"] != self.cfg.min_level:
            raise Fatal("the plan was made for another API, index, page size or minimum level")
        start, end = parse_ts(plan["window"]["start"]), parse_ts(plan["window"]["end"])
        if end > self.now() - timedelta(seconds=self.cfg.settle):
            raise Fatal("the window ends inside the settle period; plan a window that ends earlier")
        st = self.state.load()
        if st is not None and st.get("plan_sha256") != sha:
            raise Fatal("BACKFILL_STATE_DIR holds the progress of another plan: finish it or use a new state directory")
        st = st or {"plan_sha256": sha, "next_page": 0, "counts": {}}
        counts = Counter(st.get("counts") or {})
        orgs = plan["filters"]["orgs"] or None
        include_q = plan["filters"]["include_quarantine"]
        gap = 60.0 / max(1, batches_per_minute)
        pages = plan["pages"]
        for i in range(st["next_page"], len(pages)):
            p = pages[i]
            hits = self._retry(lambda: self.search(start, end, p["after"], self.cfg.page))
            last = valid_sort(hits[-1]["sort"]) if hits else None
            if len(hits) != p["count"] or last != p["last"]:
                raise Stale(f"page {i}: the index window changed since the plan")
            rows = self._retry(lambda: self.classified_page(hits))
            if owner_digest([(r["id"], self.owner(r)) for r in rows]) != p["digest"]:
                raise Stale(f"page {i}: ownership changed since the plan (mappings, agent groups or sources); re-plan")
            chosen = [r for r in rows if self.eligible(r, orgs, include_q) and r["alert"] is not None][:p["eligible"]]
            elig = [r["alert"] for r in chosen]
            counts["scanned"] += len(rows)
            counts["eligible"] += len(elig)
            counts["invalid"] += sum(1 for r in rows if r["verdict"] == "invalid")
            if elig:
                bid = "bkf-" + hashlib.sha256(f"{sha}:{i}".encode()).hexdigest()[:48]
                self.state.ledger({"kind": "intent", "page": i, "batch_id": bid, "ids": [a["id"] for a in elig],
                                   "new_ids": [r["id"] for r in chosen if r["verdict"] == "new"]})
                got = self._retry(lambda: self.deliver(bid, elig))
                self.state.ledger({"kind": "ack", "page": i, "batch_id": bid, "ack": got})
                for k, v in got.items():
                    counts[k] += v
            st = {"plan_sha256": sha, "next_page": i + 1, "counts": dict(counts)}
            self.state.save(st)
            log("info", "import_page", page=i + 1, pages=len(pages), **{k: counts.get(k, 0) for k in
                ("scanned", "eligible", "accepted", "duplicates", "quarantined", "replayed", "invalid", "failed")})
            if gap and i + 1 < len(pages):
                self.sleep(gap)
        log("info", "import_complete", **dict(counts))
        return dict(counts)

    def _retry(self, fn):
        delay = 2.0
        for attempt in range(self.cfg.max_retries + 1):
            try:
                return fn()
            except Retryable as e:
                if attempt == self.cfg.max_retries:
                    self.failed += 1
                    raise
                log("warning", "retry", reason=str(e), attempt=attempt + 1, retry_in_seconds=delay)
                self.sleep(delay)
                delay = min(120.0, delay * 2)


def build(env: Dict[str, str]) -> Backfill:
    cfg = BackfillConfig(env)
    state = BackfillState(cfg.state_dir, cfg.forwarder_state_dir)
    state.lock()
    return Backfill(cfg, api=Http("api", cfg.api_ca, cfg.timeout), indexer=Http("indexer", cfg.indexer_ca, cfg.timeout),
                    manager=Http("manager", cfg.manager_ca, cfg.timeout), state=state)


def _ts(value: str, name: str) -> datetime:
    t = parse_ts(value)
    if t is None:
        raise Fatal(f"{name} must be an ISO timestamp with a timezone")
    return t


def main(argv=None, env=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m novrsoc_forwarder.backfill")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan", help="read-only classification of a window; writes a plan and a report")
    p.add_argument("--start", required=True)
    p.add_argument("--end", required=True)
    p.add_argument("--plan", required=True)
    p.add_argument("--report")
    p.add_argument("--org", action="append", default=[], help="only these organization slugs are eligible")
    p.add_argument("--limit", type=int, help="at most this many eligible alerts (a pilot)")
    p.add_argument("--include-quarantine", action="store_true", help="also send unattributable alerts (they are quarantined)")
    p.add_argument("--live-start", help="the live forwarder's start: the window must end at or before it")
    p.add_argument("--pace-seconds", type=float, default=1.0)
    i = sub.add_parser("import", help="import exactly an approved plan")
    i.add_argument("--plan", required=True)
    i.add_argument("--approve", required=True, help="the plan's sha256, as printed by `plan`")
    i.add_argument("--batches-per-minute", type=int, default=30)
    sub.add_parser("status", help="progress of the import in BACKFILL_STATE_DIR")
    args = ap.parse_args(argv)
    env = os.environ if env is None else env
    try:
        bf = build(env)
    except Fatal as e:
        log("error", "not_started", reason=str(e))
        return EXIT_FATAL
    try:
        if args.cmd == "status":
            print(json.dumps(bf.state.load() or {"next_page": 0, "counts": {}}, indent=2))
            return 0
        if args.cmd == "plan":
            start, end = _ts(args.start, "--start"), _ts(args.end, "--end")
            if end <= start:
                raise Fatal("--end must be after --start")
            if args.live_start and end > _ts(args.live_start, "--live-start"):
                raise Fatal("the window overlaps the live forwarder (--end is after --live-start)")
            if end > bf.now() - timedelta(seconds=bf.cfg.settle):
                raise Fatal("--end is inside the settle period")
            if args.limit is not None and args.limit < 1:
                raise Fatal("--limit must be at least 1")
            if os.path.exists(args.plan):
                raise Fatal("--plan already exists (a plan is never overwritten)")
            plan, report = bf.plan(start, end, orgs=args.org or None, limit=args.limit, include_quarantine=args.include_quarantine,
                                   pace=args.pace_seconds)
            with open(args.plan, "x", encoding="utf-8") as f:
                json.dump(plan, f, indent=1)
            if args.report:
                with open(args.report, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2)
            print(json.dumps({k: report[k] for k in ("plan_sha256", "window", "filters", "limit", "counts", "by_organization",
                                                     "quarantine_by_reason")}, indent=2))
            return 0
        with open(args.plan, encoding="utf-8") as f:
            plan = json.load(f)
        bf.run_import(plan, args.approve, batches_per_minute=args.batches_per_minute)
        return 0
    except Stale as e:
        log("error", "stale_plan", reason=str(e))
        return EXIT_STALE
    except Fatal as e:
        log("error", "stopped", reason=str(e))
        return EXIT_FATAL
    except Retryable as e:
        log("warning", "interrupted", reason=str(e), failed=bf.failed, resume="run the same command again (an import resumes at its checkpoint)")
        return EXIT_RETRY
    finally:
        bf.state.unlock()


if __name__ == "__main__":
    raise SystemExit(main())
