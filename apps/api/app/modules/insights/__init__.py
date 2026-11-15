"""Threat Insights (Phase 5, workstream F): organization-scoped indicators, deterministic matching against the
organization's own alerts, correlation groups and STIX 2.1 export. No model is involved; no data crosses
organizations (RLS on every table, the engine never takes an organization argument for reads).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import service as audit
from app.auth.deps import Principal, ServicePrincipal, client_ip, current_service, require
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.insights import engine, stix_store
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.insights import (CorrelationGroup, CorrelationList, FeedRun, FeedRunList, IndicatorContext, IndicatorImport,
                                           IndicatorImportResult, IndicatorList, RelatedObject, StixIngest, StixIngestResult,
                                           IndicatorProvenance, IndicatorRecord, InsightFeedback, InsightMatchList,
                                           InsightMatchView, MatchConfidence, MatchRunResult, Observable)

MODULE = ModuleInfo(name="insights", workstream="F", prefix="/api/v1/insights",
                    summary="Threat Insights: organization-scoped indicators, deterministic matching, correlation, STIX 2.1")
router = APIRouter(prefix="/api/v1/insights", tags=["insights"], responses=ERRORS)

_IND_COLS = "id, type, value, tlp, confidence, valid_from, valid_until, stix_id, source, source_ref, imported_label, imported_at"


def _record(r) -> IndicatorRecord:
    return IndicatorRecord(id=r.id, type=r.type, value=r.value, tlp=r.tlp, confidence=r.confidence, valid_from=r.valid_from,
                           valid_until=r.valid_until, stix_id=r.stix_id,
                           provenance=IndicatorProvenance(source=r.source, source_ref=r.source_ref, imported_by=r.imported_label,
                                                          imported_at=r.imported_at))


@router.post("/indicators", response_model=IndicatorImportResult, summary="Import indicators (plain or a STIX 2.1 bundle)")
def import_indicators(body: IndicatorImport, request: Request, p: Principal = Depends(require("intel:manage")),
                      conn: Connection = Depends(request_connection)) -> IndicatorImportResult:
    items, skipped = [], []
    for ind in body.indicators:
        if engine.normalize(ind.type.value, ind.value) is None:
            skipped.append(f"{ind.type.value}: value is not valid")
            continue
        items.append((ind.model_copy(update={"source": body.source}), "", None))
    if body.stix_bundle is not None:
        parsed, why = engine.parse_stix_bundle(body.stix_bundle)
        items.extend(parsed)
        skipped.extend(why)
    if not items and not skipped:
        raise ApiError(422, "validation_error", "Nothing to import")
    c = engine.upsert_indicators(conn, p.org_id, items, source=body.source, tlp=body.tlp.value, user_id=p.user_id, label=p.email)
    audit.record("TI_INDICATORS_IMPORTED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="ti_indicators", resource_id=body.source, request_id=request.state.request_id, ip=client_ip(request),
                 details={"imported": c.imported, "unchanged": c.unchanged, "skipped": len(skipped)})
    return IndicatorImportResult(imported=c.imported, unchanged=c.unchanged, skipped=skipped[:200])


@router.get("/indicators", response_model=IndicatorList, summary="Indicators of the active organization")
def list_indicators(limit: int = Query(200, ge=1, le=1000), p: Principal = Depends(require("intel:read")),
                    conn: Connection = Depends(request_connection)) -> IndicatorList:
    rows = conn.execute(text(f"SELECT {_IND_COLS} FROM novrsoc.ti_indicators ORDER BY imported_at DESC LIMIT :n"), {"n": limit}).all()
    return IndicatorList(items=[_record(r) for r in rows])


@router.post("/match", response_model=MatchRunResult, summary="Match indicators against the organization's recent alerts")
def run_match(request: Request, hours: int = Query(24, ge=1, le=24 * 31), p: Principal = Depends(require("intel:manage")),
              conn: Connection = Depends(request_connection)) -> MatchRunResult:
    scanned, observables, new = engine.match_alerts(conn, since=datetime.now(timezone.utc) - timedelta(hours=hours))
    audit.record("TI_MATCH_RUN", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_matches",
                 request_id=request.state.request_id, ip=client_ip(request), details={"scanned": scanned, "new": new})
    return MatchRunResult(alerts_scanned=scanned, observables=observables, new_matches=new)


@router.get("/matches", response_model=InsightMatchList, summary="Indicator matches in the organization's alerts")
def list_matches(alert_id: uuid.UUID | None = None, limit: int = Query(200, ge=1, le=1000),
                 p: Principal = Depends(require("intel:read")), conn: Connection = Depends(request_connection)) -> InsightMatchList:
    rows = conn.execute(text(f"""SELECT m.id AS mid, m.alert_id, m.observable_type, m.observable_value, m.source_field, m.matched_at,
                                        m.confidence AS score, m.confidence_band, m.confidence_reasons, m.verdict,
                                        {', '.join('i.' + c for c in _IND_COLS.split(', '))}
                                 FROM novrsoc.ti_matches m JOIN novrsoc.ti_indicators i ON i.id = m.indicator_id AND i.org_id = m.org_id
                                 WHERE (CAST(:a AS uuid) IS NULL OR m.alert_id = CAST(:a AS uuid))
                                 ORDER BY m.matched_at DESC LIMIT :n"""), {"a": alert_id, "n": limit}).all()
    return InsightMatchList(items=[InsightMatchView(
        id=r.mid, indicator=_record(r), alert_id=r.alert_id, matched_at=r.matched_at, verdict=r.verdict,
        observable=Observable(type=r.observable_type, value=r.observable_value, source_field=r.source_field),
        confidence=MatchConfidence(score=r.score, band=r.confidence_band, reasons=list(r.confidence_reasons))) for r in rows])


@router.post("/matches/{match_id}/verdict", response_model=InsightMatchList, summary="Analyst verdict on a match")
def set_verdict(match_id: uuid.UUID, body: InsightFeedback, request: Request, p: Principal = Depends(require("intel:manage")),
                conn: Connection = Depends(request_connection)) -> InsightMatchList:
    if body.match_id != match_id:
        raise ApiError(422, "validation_error", "match_id in the body must match the path")
    r = conn.execute(text("""UPDATE novrsoc.ti_matches SET verdict = :v, verdict_by = :u, verdict_note = :n, verdict_at = now()
                             WHERE id = :id RETURNING alert_id"""), {"v": body.verdict, "u": p.user_id, "n": body.note, "id": match_id}).first()
    if r is None:
        raise not_found("Match not found")
    audit.record("TI_MATCH_VERDICT", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_match",
                 resource_id=str(match_id), request_id=request.state.request_id, ip=client_ip(request), details={"verdict": body.verdict})
    return list_matches(alert_id=r.alert_id, limit=200, p=p, conn=conn)


@router.get("/correlations", response_model=CorrelationList, summary="Correlation groups over the organization's alerts")
def correlations(hours: int = Query(24, ge=1, le=24 * 31), p: Principal = Depends(require("intel:read")),
                 conn: Connection = Depends(request_connection)) -> CorrelationList:
    groups = engine.correlate(conn, since=datetime.now(timezone.utc) - timedelta(hours=hours))
    return CorrelationList(window_hours=hours, items=[CorrelationGroup(**g) for g in groups])


@router.get("/stix", summary="STIX 2.1 bundle: the organization's indicators and sightings in its alerts")
def stix_export(kind: Literal["indicators", "all"] = "all", p: Principal = Depends(require("intel:read")),
                conn: Connection = Depends(request_connection)) -> dict:
    inds = conn.execute(text(f"SELECT {_IND_COLS} FROM novrsoc.ti_indicators ORDER BY imported_at LIMIT 5000")).all()
    objects = [engine.stix_indicator(r) for r in inds]
    if kind == "all":
        by_id = {r.id: r.stix_id for r in inds}
        for m in conn.execute(text("""SELECT id, indicator_id, matched_at, confidence FROM novrsoc.ti_matches
                                      WHERE verdict <> 'false_positive' ORDER BY matched_at LIMIT 5000""")).all():
            if m.indicator_id in by_id:
                ts = engine._ts(m.matched_at)
                objects.append({"type": "sighting", "spec_version": "2.1", "id": f"sighting--{m.id}", "created": ts,
                                "modified": ts, "sighting_of_ref": by_id[m.indicator_id], "count": 1,
                                "first_seen": ts, "last_seen": ts, "confidence": m.confidence})
    return engine.stix_bundle(objects)


# ---------------------------------------------------------------- STIX 2.1 store and TAXII feed ingest
@router.post("/stix/bundles", response_model=StixIngestResult, summary="Upload a STIX 2.1 bundle (validated, stored, related)")
def upload_bundle(body: StixIngest, request: Request, p: Principal = Depends(require("intel:manage")),
                  conn: Connection = Depends(request_connection)) -> StixIngestResult:
    out = stix_store.ingest_bundle(conn, p.org_id, body.bundle, source=body.source, collection=body.collection, user_id=p.user_id, label=p.email)
    audit.record("TI_STIX_INGESTED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_feed",
                 resource_id=body.source, request_id=request.state.request_id, ip=client_ip(request),
                 details={k: v for k, v in out.items() if k != "rejected"})
    return StixIngestResult(**out)


@router.post("/ingest/stix", response_model=StixIngestResult, summary="TAXII feeder (machine identity): deliver a STIX 2.1 bundle")
def feeder_ingest(body: StixIngest, request: Request, s: ServicePrincipal = Depends(current_service),
                  conn: Connection = Depends(request_connection)) -> StixIngestResult:
    if s.kind != "ti_feeder" or "intel:ingest" not in s.scopes:
        audit.record("TI_FEED_REFUSED", "denied", org_id=s.org_id, actor_type="service", actor_id=s.identity_id,
                     resource_type="service_identity", resource_id=str(s.identity_id), request_id=request.state.request_id, ip=client_ip(request))
        raise ApiError(403, "forbidden", "Only a ti_feeder identity with the intel:ingest scope may deliver feeds")
    conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(s.org_id)})
    out = stix_store.ingest_bundle(conn, s.org_id, body.bundle, source=body.source, collection=body.collection, label=f"feeder:{s.identity_id}")
    audit.record("TI_STIX_INGESTED", "success", org_id=s.org_id, actor_type="service", actor_id=s.identity_id, resource_type="ti_feed",
                 resource_id=body.source, request_id=request.state.request_id, ip=client_ip(request),
                 details={k: v for k, v in out.items() if k != "rejected"})
    return StixIngestResult(**out)


@router.get("/feed-runs", response_model=FeedRunList, summary="Recent STIX/TAXII ingest runs")
def feed_runs(p: Principal = Depends(require("intel:read")), conn: Connection = Depends(request_connection)) -> FeedRunList:
    rows = conn.execute(text("SELECT * FROM novrsoc.ti_feed_runs ORDER BY received_at DESC LIMIT 50")).all()
    return FeedRunList(items=[FeedRun(id=r.id, source=r.source, collection=r.collection, objects_received=r.objects_received,
                                      objects_stored=r.objects_stored, indicators_imported=r.indicators_imported, rejected=r.rejected,
                                      received_at=r.received_at) for r in rows])


@router.get("/indicators/{indicator_id}/context", response_model=IndicatorContext, summary="STIX relationship context of an indicator")
def indicator_context(indicator_id: uuid.UUID, p: Principal = Depends(require("intel:read")),
                      conn: Connection = Depends(request_connection)) -> IndicatorContext:
    r = conn.execute(text(f"SELECT {_IND_COLS} FROM novrsoc.ti_indicators WHERE id = :i"), {"i": indicator_id}).first()
    if r is None:
        raise not_found("Indicator not found")
    ids = {r.stix_id, *stix_store.indicator_stix_ids(conn, r.type, r.value)}
    related = [x for sid in sorted(ids) for x in stix_store.related(conn, sid)]
    return IndicatorContext(indicator=_record(r), related=[RelatedObject(**x) for x in related])


# ---------------------------------------------------------------- consolidation: threat actors
# Attribution is explicit: verified (cited sources), suspected, or unknown. NovrSOC never names an actor itself; an
# actor is "observed in this organization" only through a VERIFIED link to the organization's own records.
from novrsoc_contracts.v1.insights import (ActorLinkCreate, ActorLinkView, ActorSource, CveImport, CveImportResult,  # noqa: E402
                                           CveIntelList, CveIntelView, SnapshotCreate, SnapshotList, SnapshotView, ThreatActorCreate,
                                           ThreatActorList, ThreatActorView)
import hashlib as _hashlib  # noqa: E402
import json as _json  # noqa: E402
import re as _re  # noqa: E402

_LINK_EXISTS = {
    "indicator": "SELECT 1 FROM novrsoc.ti_indicators WHERE id = CAST(:r AS uuid)",
    "alert": "SELECT 1 FROM novrsoc.alerts WHERE id = CAST(:r AS uuid)",
    "case": "SELECT 1 FROM novrsoc.cases WHERE id = CAST(:r AS uuid)",
    "asset": "SELECT 1 FROM novrsoc.assets WHERE id = CAST(:r AS uuid)",
}
_UUID = _re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CVE = _re.compile(r"^CVE-\d{4}-\d{4,7}$")


def _link_exists(conn: Connection, link_type: str, ref: str) -> bool:
    if link_type == "cve":
        return bool(_CVE.match(ref))
    if not _UUID.match(ref.lower()):
        return False
    return conn.execute(text(_LINK_EXISTS[link_type]), {"r": ref}).first() is not None


def _actor(conn: Connection, r) -> ThreatActorView:
    links = conn.execute(text("SELECT * FROM novrsoc.ti_actor_links WHERE actor_id = :a ORDER BY created_at"), {"a": r.id}).all()
    views = [ActorLinkView(id=l.id, link_type=l.link_type, ref_id=l.ref_id, association=l.association, rationale=l.rationale,
                           created_label=l.created_label, created_at=l.created_at, exists=_link_exists(conn, l.link_type, l.ref_id)) for l in links]
    observed = any(v.association == "verified" and v.exists and v.link_type in ("alert", "case", "asset") for v in views)
    return ThreatActorView(id=r.id, name=r.name, aliases=list(r.aliases), attribution=r.attribution, confidence=r.confidence,
                           description=r.description, motivations=list(r.motivations), target_sectors=list(r.target_sectors),
                           target_regions=list(r.target_regions), techniques=list(r.techniques), first_seen=r.first_seen, last_seen=r.last_seen,
                           sources=[ActorSource(**s) for s in (r.sources or [])], created_label=r.created_label, created_at=r.created_at,
                           updated_at=r.updated_at, links=views, observed_in_organization=observed)


@router.get("/actors", response_model=ThreatActorList, summary="Threat actor profiles of the organization (nothing pre-loaded)")
def list_actors(q: str | None = Query(None, max_length=120), attribution: Literal["verified", "suspected", "unknown"] | None = None,
                p: Principal = Depends(require("intel:read")), conn: Connection = Depends(request_connection)) -> ThreatActorList:
    rows = conn.execute(text("""SELECT * FROM novrsoc.ti_threat_actors WHERE (CAST(:a AS text) IS NULL OR attribution = :a)
                                AND (CAST(:q AS text) IS NULL OR name ILIKE :ql OR :qx = ANY(aliases) OR :qx = ANY(target_sectors))
                                ORDER BY CASE attribution WHEN 'verified' THEN 0 WHEN 'suspected' THEN 1 ELSE 2 END, name"""),
                        {"a": attribution, "q": q, "ql": f"%{q}%" if q else None, "qx": q}).all()
    return ThreatActorList(items=[_actor(conn, r) for r in rows])


def _actor_params(body: ThreatActorCreate) -> dict:
    return {"n": body.name, "al": body.aliases, "at": body.attribution, "c": body.confidence, "d": body.description, "m": body.motivations,
            "ts": body.target_sectors, "tr": body.target_regions, "te": body.techniques, "fs": body.first_seen, "ls": body.last_seen,
            "src": _json.dumps([s.model_dump(mode="json") for s in body.sources])}


@router.post("/actors", response_model=ThreatActorView, status_code=201, summary="Record a threat actor profile")
def create_actor(body: ThreatActorCreate, request: Request, p: Principal = Depends(require("intel:manage")),
                 conn: Connection = Depends(request_connection)) -> ThreatActorView:
    if conn.execute(text("SELECT 1 FROM novrsoc.ti_threat_actors WHERE name = :n"), {"n": body.name}).first():
        raise ApiError(409, "conflict", "An actor with this name already exists")
    r = conn.execute(text("""INSERT INTO novrsoc.ti_threat_actors (org_id, name, aliases, attribution, confidence, description, motivations,
                                target_sectors, target_regions, techniques, first_seen, last_seen, sources, created_by, created_label)
                             VALUES (:o, :n, :al, :at, :c, :d, :m, :ts, :tr, :te, :fs, :ls, CAST(:src AS jsonb), :u, :l) RETURNING *"""),
                     {**_actor_params(body), "o": p.org_id, "u": p.user_id, "l": p.email}).one()
    audit.record("TI_ACTOR_CREATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_actor",
                 resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"attribution": body.attribution, "sources": len(body.sources)})
    return _actor(conn, r)


@router.put("/actors/{actor_id}", response_model=ThreatActorView, summary="Update a threat actor profile")
def update_actor(actor_id: uuid.UUID, body: ThreatActorCreate, request: Request, p: Principal = Depends(require("intel:manage")),
                 conn: Connection = Depends(request_connection)) -> ThreatActorView:
    r = conn.execute(text("""UPDATE novrsoc.ti_threat_actors SET name = :n, aliases = :al, attribution = :at, confidence = :c, description = :d,
                               motivations = :m, target_sectors = :ts, target_regions = :tr, techniques = :te, first_seen = :fs, last_seen = :ls,
                               sources = CAST(:src AS jsonb), updated_at = now() WHERE id = :id RETURNING *"""),
                     {**_actor_params(body), "id": actor_id}).first()
    if r is None:
        raise not_found("Actor not found")
    audit.record("TI_ACTOR_UPDATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_actor",
                 resource_id=str(actor_id), request_id=request.state.request_id, ip=client_ip(request), details={"attribution": body.attribution})
    return _actor(conn, r)


@router.post("/actors/{actor_id}/links", response_model=ThreatActorView, status_code=201,
             summary="Associate an actor with an indicator, CVE, case, alert or asset (verified or suspected, with a rationale)")
def link_actor(actor_id: uuid.UUID, body: ActorLinkCreate, request: Request, p: Principal = Depends(require("intel:manage")),
               conn: Connection = Depends(request_connection)) -> ThreatActorView:
    r = conn.execute(text("SELECT * FROM novrsoc.ti_threat_actors WHERE id = :i"), {"i": actor_id}).first()
    if r is None:
        raise not_found("Actor not found")
    if body.association == "verified" and r.attribution != "verified":
        raise ApiError(422, "validation_error", "A verified association needs a verified actor profile (with cited sources)")
    ref = body.ref_id.strip().upper() if body.link_type == "cve" else body.ref_id.strip().lower()
    if not _link_exists(conn, body.link_type, ref):
        raise not_found(f"The {body.link_type} does not exist in this organization")
    conn.execute(text("""INSERT INTO novrsoc.ti_actor_links (org_id, actor_id, link_type, ref_id, association, rationale, created_by, created_label)
                         VALUES (:o, :a, :t, :r, :asn, :ra, :u, :l)
                         ON CONFLICT (actor_id, link_type, ref_id) DO UPDATE SET association = EXCLUDED.association, rationale = EXCLUDED.rationale"""),
                 {"o": p.org_id, "a": actor_id, "t": body.link_type, "r": ref, "asn": body.association, "ra": body.rationale, "u": p.user_id,
                  "l": p.email})
    audit.record("TI_ACTOR_LINKED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_actor",
                 resource_id=str(actor_id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"link_type": body.link_type, "ref": ref, "association": body.association})
    return _actor(conn, r)


@router.delete("/actors/{actor_id}/links/{link_id}", response_model=ThreatActorView, summary="Remove an actor association")
def unlink_actor(actor_id: uuid.UUID, link_id: uuid.UUID, request: Request, p: Principal = Depends(require("intel:manage")),
                 conn: Connection = Depends(request_connection)) -> ThreatActorView:
    r = conn.execute(text("SELECT * FROM novrsoc.ti_threat_actors WHERE id = :i"), {"i": actor_id}).first()
    if r is None or conn.execute(text("DELETE FROM novrsoc.ti_actor_links WHERE id = :l AND actor_id = :a RETURNING id"),
                                 {"l": link_id, "a": actor_id}).first() is None:
        raise not_found("Association not found")
    audit.record("TI_ACTOR_UNLINKED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_actor",
                 resource_id=str(actor_id), request_id=request.state.request_id, ip=client_ip(request), details={"link": str(link_id)})
    return _actor(conn, r)


# ---------------------------------------------------------------- consolidation: CVE intelligence and snapshots
def _cve_merged() -> str:
    from app.insights.cve import merged
    return merged()


def _insert_cve(conn: Connection, org_id, rec, source: str, label: str) -> None:
    conn.execute(text("""INSERT INTO novrsoc.ti_cve_records (org_id, cve_id, cvss_v3, cvss_vector, epss, kev, kev_added, published_at,
                                                             description, source, imported_label)
                         VALUES (:o, :c, :s, :v, :e, :k, :ka, :p, :d, :src, :l)"""),
                 {"o": org_id, "c": rec["cve_id"], "s": rec.get("cvss_v3"), "v": rec.get("cvss_vector"), "e": rec.get("epss"),
                  "k": bool(rec.get("kev")), "ka": rec.get("kev_added"), "p": rec.get("published"), "d": (rec.get("description") or "")[:4000],
                  "src": source, "l": label})


@router.post("/cves/import", response_model=CveImportResult, summary="Import CVE intelligence (records, or a CISA KEV catalog file)")
def import_cves(body: CveImport, request: Request, p: Principal = Depends(require("intel:manage")),
                conn: Connection = Depends(request_connection)) -> CveImportResult:
    records = [r.model_dump(mode="json") for r in body.records]
    skipped = []
    if body.kev_catalog is not None:
        vulns = body.kev_catalog.get("vulnerabilities")
        if not isinstance(vulns, list):
            raise ApiError(422, "validation_error", "A KEV catalog has a `vulnerabilities` list")
        for v in vulns[:20000]:
            cve = str((v or {}).get("cveID", "")).strip().upper()
            if not _CVE.match(cve):
                skipped.append(f"not a CVE id: {cve[:40]}")
                continue
            added = str(v.get("dateAdded") or "")[:10] or None
            records.append({"cve_id": cve, "kev": True, "kev_added": added if added and _re.match(r"^\d{4}-\d{2}-\d{2}$", added) else None,
                            "description": " - ".join(x for x in (v.get("vulnerabilityName"), v.get("shortDescription")) if x)[:4000]})
    if not records:
        raise ApiError(422, "validation_error", "Nothing to import")
    for rec in records:
        _insert_cve(conn, p.org_id, rec, body.source, p.email)
    audit.record("TI_CVES_IMPORTED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_cves",
                 resource_id=body.source, request_id=request.state.request_id, ip=client_ip(request),
                 details={"imported": len(records), "skipped": len(skipped)})
    return CveImportResult(imported=len(records), skipped=skipped[:200])


@router.post("/cves/import-stix", response_model=CveImportResult, summary="Derive CVE records from STIX 2.1 vulnerability objects already stored")
def import_cves_from_stix(request: Request, p: Principal = Depends(require("intel:manage")),
                          conn: Connection = Depends(request_connection)) -> CveImportResult:
    n, skipped = 0, []
    for r in conn.execute(text("""SELECT DISTINCT ON (stix_id) stix_id, object, source FROM novrsoc.ti_stix_objects
                                  WHERE type = 'vulnerability' ORDER BY stix_id, modified DESC""")):
        obj = r.object or {}
        cve = next((x.get("external_id", "").upper() for x in obj.get("external_references", []) if x.get("source_name") == "cve"), "") \
            or str(obj.get("name", "")).upper()
        if not _CVE.match(cve):
            skipped.append(f"{r.stix_id}: no CVE reference")
            continue
        _insert_cve(conn, p.org_id, {"cve_id": cve, "description": obj.get("description", "")}, f"stix:{r.source}"[:80], p.email)
        n += 1
    audit.record("TI_CVES_IMPORTED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_cves",
                 resource_id="stix", request_id=request.state.request_id, ip=client_ip(request), details={"imported": n})
    return CveImportResult(imported=n, skipped=skipped[:200])


@router.get("/cves", response_model=CveIntelList, summary="CVE intelligence, correlated with the organization's open findings")
def list_cves(kev_only: bool = False, q: str | None = Query(None, max_length=40), p: Principal = Depends(require("intel:read")),
              conn: Connection = Depends(request_connection)) -> CveIntelList:
    rows = conn.execute(text("""
        WITH latest AS (""" + _cve_merged() + """)
        SELECT l.*,
               (SELECT count(*) FROM novrsoc.vms_findings f WHERE l.cve_id = ANY(f.cves) AND f.status NOT IN ('verified', 'risk_accepted')) AS findings,
               (SELECT count(DISTINCT f.asset_id) FROM novrsoc.vms_findings f WHERE l.cve_id = ANY(f.cves)
                  AND f.status NOT IN ('verified', 'risk_accepted') AND f.asset_id IS NOT NULL) AS assets,
               (SELECT array_agg(a.name || ' (' || k.association || ')') FROM novrsoc.ti_actor_links k
                  JOIN novrsoc.ti_threat_actors a ON a.id = k.actor_id WHERE k.link_type = 'cve' AND k.ref_id = l.cve_id) AS actors
        FROM latest l WHERE (NOT :kev OR l.kev) AND (CAST(:q AS text) IS NULL OR l.cve_id ILIKE :ql)
        ORDER BY (SELECT count(*) FROM novrsoc.vms_findings f WHERE l.cve_id = ANY(f.cves)) DESC, l.kev DESC, l.cvss_v3 DESC NULLS LAST
        LIMIT 500"""), {"kev": kev_only, "q": q, "ql": f"%{q}%" if q else None}).all()
    missing = [r[0] for r in conn.execute(text("""SELECT DISTINCT c FROM novrsoc.vms_findings f, unnest(f.cves) c
                                                  WHERE f.status NOT IN ('verified', 'risk_accepted')
                                                  AND NOT EXISTS (SELECT 1 FROM novrsoc.ti_cve_records r WHERE r.cve_id = c) ORDER BY c LIMIT 200"""))]
    return CveIntelList(finding_cves_without_intel=missing, items=[CveIntelView(
        cve_id=r.cve_id, cvss_v3=float(r.cvss_v3) if r.cvss_v3 is not None else None, cvss_vector=r.cvss_vector,
        epss=float(r.epss) if r.epss is not None else None, kev=r.kev, kev_added=r.kev_added, published=r.published_at,
        description=r.description, source=r.source, captured_at=r.captured_at, snapshots=r.snaps, open_findings=r.findings,
        affected_assets=r.assets, actors=list(r.actors or [])) for r in rows])


def _snapshot_view(r) -> SnapshotView:
    return SnapshotView(id=r.id, kind=r.kind, subject=r.subject, content=r.content, sha256=r.sha256, reason=r.reason,
                        captured_label=r.captured_label, captured_at=r.captured_at)


@router.post("/snapshots", response_model=SnapshotView, status_code=201,
             summary="Freeze the current CVSS (per CVE) or IOC (per indicator) state as evidence, with a checksum")
def create_snapshot(body: SnapshotCreate, request: Request, p: Principal = Depends(require("intel:manage")),
                    conn: Connection = Depends(request_connection)) -> SnapshotView:
    now = datetime.now(timezone.utc).isoformat()
    if body.kind == "cvss":
        cve = body.subject.strip().upper()
        recs = conn.execute(text("SELECT * FROM novrsoc.ti_cve_records WHERE cve_id = :c ORDER BY captured_at"), {"c": cve}).all()
        if not recs:
            raise not_found("No intelligence is recorded for this CVE")
        findings = conn.execute(text("""SELECT id, host, status, severity FROM novrsoc.vms_findings WHERE :c = ANY(cves) ORDER BY id"""), {"c": cve}).all()
        content = {"captured_at": now, "cve": cve, "records": [{"cvss_v3": float(r.cvss_v3) if r.cvss_v3 is not None else None,
                   "cvss_vector": r.cvss_vector, "epss": float(r.epss) if r.epss is not None else None, "kev": r.kev, "source": r.source,
                   "captured_at": r.captured_at.isoformat()} for r in recs],
                   "findings": [{"id": str(f.id), "host": f.host, "status": f.status, "severity": f.severity} for f in findings]}
        subject = cve
    else:
        if not _UUID.match(body.subject.strip().lower()):
            raise ApiError(422, "validation_error", "An IOC snapshot names an indicator id")
        ind = conn.execute(text(f"SELECT {_IND_COLS} FROM novrsoc.ti_indicators WHERE id = CAST(:i AS uuid)"), {"i": body.subject.strip()}).first()
        if ind is None:
            raise not_found("Indicator not found")
        matches = conn.execute(text("""SELECT verdict, count(*) AS n, max(matched_at) AS last FROM novrsoc.ti_matches WHERE indicator_id = :i
                                       GROUP BY verdict"""), {"i": ind.id}).all()
        content = {"captured_at": now, "indicator": _record(ind).model_dump(mode="json"),
                   "matches": {m.verdict: {"count": m.n, "last": m.last.isoformat()} for m in matches}}
        subject = str(ind.id)
    canonical = _json.dumps(content, sort_keys=True, default=str)
    r = conn.execute(text("""INSERT INTO novrsoc.ti_snapshots (org_id, kind, subject, content, sha256, reason, captured_by, captured_label)
                             VALUES (:o, :k, :s, CAST(:c AS jsonb), :h, :r, :u, :l) RETURNING *"""),
                     {"o": p.org_id, "k": body.kind, "s": subject, "c": canonical, "h": _hashlib.sha256(canonical.encode()).hexdigest(),
                      "r": body.reason, "u": p.user_id, "l": p.email}).one()
    audit.record("TI_SNAPSHOT_CAPTURED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="ti_snapshot",
                 resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request), details={"kind": body.kind, "subject": subject})
    return _snapshot_view(r)


@router.get("/snapshots", response_model=SnapshotList, summary="Evidence snapshots (newest first)")
def list_snapshots(subject: str | None = Query(None, max_length=300), p: Principal = Depends(require("intel:read")),
                   conn: Connection = Depends(request_connection)) -> SnapshotList:
    rows = conn.execute(text("""SELECT * FROM novrsoc.ti_snapshots WHERE (CAST(:s AS text) IS NULL OR subject = :s)
                                ORDER BY captured_at DESC LIMIT 200"""), {"s": subject}).all()
    return SnapshotList(items=[_snapshot_view(r) for r in rows])
