"""Operator and local development CLI.

  python -m app.cli bootstrap-platform --email <first admin> --out <file>
      Production first start (any environment): the platform organization and the first super_admin, once, on an
      empty database. The temporary password goes to <file> only and must be changed at first sign-in.

  python -m app.cli seed-dev --out <file.json>
      Creates a disposable platform org, two client orgs (alpha, beta), one user per role with random
      passwords, and writes the credentials to <file.json> (keep it outside the repository).
      Refused unless NOVRSOC_ENV is development/test AND the database host is loopback (Settings guard).
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import uuid
from pathlib import Path

from sqlalchemy import create_engine, text

from app import devseed
from app.core.config import LOOPBACK_HOSTS, Settings
from novrsoc_contracts.v1.platform import PLATFORM_ONLY_KINDS, SERVICE_KIND_SCOPES


def seed_dev(out: Path, if_empty: bool = False) -> int:
    settings = Settings()  # type: ignore[call-arg]
    if settings.env not in ("development", "test") or settings.database_host not in LOOPBACK_HOSTS:
        print("refused: seed-dev only runs against a loopback development/test database", file=sys.stderr)
        return 2
    owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
    if not owner_url:
        print("NOVRSOC_MIGRATION_DATABASE_URL is required (schema owner)", file=sys.stderr)
        return 2
    eng = create_engine(owner_url)
    creds: dict[str, dict] = {}
    with eng.begin() as conn:
        if conn.execute(text("SELECT count(*) FROM novrsoc.organizations")).scalar():
            if if_empty:
                print("database already seeded; nothing changed (credentials file kept as is)")
                return 0
            print("refused: database already has organizations (seed-dev is for an empty disposable database)", file=sys.stderr)
            return 2
        platform = devseed.create_org(conn, "novrsoc-platform", "NovrSOC Platform (dev)", "platform")
        alpha = devseed.create_org(conn, "dev-alpha", "Dev Alpha Ltd (disposable)")
        beta = devseed.create_org(conn, "dev-beta", "Dev Beta Ltd (disposable)")
        users = [
            ("admin@dev.novrsoc.invalid", "super_admin", platform, {}),
            ("manager@dev.novrsoc.invalid", "soc_manager", platform, {alpha: "operations"}),
            ("analyst.alpha@dev.novrsoc.invalid", "analyst", alpha, {}),
            ("analyst.beta@dev.novrsoc.invalid", "analyst", beta, {}),
            ("exec.alpha@dev.novrsoc.invalid", "executive", alpha, {}),
            ("portal.alpha@dev.novrsoc.invalid", "portal_user", alpha, {}),
        ]
        for email, role, home, assign in users:
            pw = secrets.token_urlsafe(18)
            devseed.create_user(conn, email, pw, role, home, assign)
            creds[email] = {"password": pw, "role": role}
    out.write_text(json.dumps({"orgs": {"platform": str(platform), "alpha": str(alpha), "beta": str(beta)},
                               "users": creds}, indent=1), encoding="utf-8")
    print(f"seeded disposable data; credentials written to {out}")
    return 0


def bootstrap_platform(email: str, org_name: str, out: Path) -> int:
    """Production first start: create the platform organization and the first super_admin, ONCE.
    Refused when any user or organization exists. The temporary password is written once to `out` (mode 0600), never
    printed; the account must change it at first sign-in (password_change_required). Works in any environment."""
    if out.exists():
        print("refused: --out already exists (a credential is never overwritten)", file=sys.stderr)
        return 2
    email = email.strip().lower()
    if "@" not in email or len(email) > 254:
        print("refused: --email must be an email address", file=sys.stderr)
        return 2
    owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
    if not owner_url:
        print("NOVRSOC_MIGRATION_DATABASE_URL is required (schema owner)", file=sys.stderr)
        return 2
    password = secrets.token_urlsafe(18)
    with create_engine(owner_url).begin() as conn:
        conn.execute(text("LOCK TABLE novrsoc.users, novrsoc.organizations IN EXCLUSIVE MODE"))
        if conn.execute(text("SELECT (SELECT count(*) FROM novrsoc.users) + (SELECT count(*) FROM novrsoc.organizations)")).scalar():
            print("refused: the database already has organizations or users (bootstrap runs once, on an empty database)",
                  file=sys.stderr)
            return 2
        platform = devseed.create_org(conn, "novrsoc-platform", org_name, "platform")
        uid = devseed.create_user(conn, email, password, "super_admin", platform)
        conn.execute(text("UPDATE novrsoc.users SET password_change_required = true WHERE id = :u"), {"u": uid})
        conn.execute(text("""INSERT INTO novrsoc.audit_events (org_id, actor_type, actor_label, action, outcome, resource_type, resource_id)
                             VALUES (:o, 'system', 'app.cli', 'PLATFORM_BOOTSTRAPPED', 'success', 'user', :u)"""),
                     {"o": platform, "u": str(uid)})
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(password + "\n")
    print(f"created the platform organization and super_admin {email}; temporary password written to {out} "
          "(change it at first sign-in, then delete the file)")
    return 0


DEV_GROUPS = {"dev-alpha": ("nv-alpha-servers", "nv-alpha-workstations"), "dev-beta": ("nv-beta-servers",)}


def seed_dev_fixtures() -> int:
    """Idempotent: map the dev organizations' Wazuh agent groups and ingest the LOCAL FIXTURE alerts through the
    real ingest service (organization from the group map; the unmapped lab alert is quarantined). Loopback only."""
    settings = Settings()  # type: ignore[call-arg]
    if settings.env not in ("development", "test") or settings.database_host not in LOOPBACK_HOSTS:
        print("refused: seed-dev-fixtures only runs against a loopback development/test database", file=sys.stderr)
        return 2
    from app.connectors.wazuh_fixture import load_fixture
    from app.modules.soc.service import ingest_alerts
    from novrsoc_contracts.v1.soc import WazuhAlertIn
    owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
    eng = create_engine(owner_url)
    with eng.begin() as conn:
        orgs = dict(conn.execute(text("SELECT slug::text, id FROM novrsoc.organizations WHERE slug IN ('dev-alpha', 'dev-beta')")).all())
        if len(orgs) != 2:
            print("refused: run seed-dev first (dev-alpha and dev-beta are missing)", file=sys.stderr)
            return 2
        for slug, groups in DEV_GROUPS.items():
            for g in groups:
                conn.execute(text("""INSERT INTO novrsoc.wazuh_group_mappings (org_id, group_name) VALUES (:o, :g)
                                     ON CONFLICT (group_name) DO NOTHING"""), {"o": orgs[slug], "g": g})
        alerts = [WazuhAlertIn.model_validate(a) for a in load_fixture()["alerts"]]
        c = ingest_alerts(conn, alerts, source="local_fixture")
    print(f"local fixtures: group mappings ensured; alerts accepted={c.accepted} duplicates={c.duplicates} quarantined={c.quarantined}")
    return 0


# Kinds and the scopes each may hold: the same definition the API enforces (novrsoc_contracts.v1.platform).
KINDS = tuple(SERVICE_KIND_SCOPES)


def create_service_identity(kind: str, name: str, org_slug: str, scopes: list[str], out: Path) -> int:
    """Issue one organization-bound machine credential (nsk_). The secret is written ONCE to `out` (mode 0600) and never
    printed. Works in any environment: it is the operator tool for issuing forwarder / worker / feeder credentials.
    Without --scope the kind's own scopes are granted; any other scope is refused (never silently dropped)."""
    if kind not in KINDS:
        print(f"refused: --kind must be one of {', '.join(KINDS)}", file=sys.stderr)
        return 2
    allowed = SERVICE_KIND_SCOPES[kind]
    scopes = sorted(set(scopes)) if scopes else sorted(allowed)
    if not set(scopes) <= allowed:
        print(f"refused: a {kind} identity may only hold {', '.join(sorted(allowed))} (got {', '.join(scopes)})", file=sys.stderr)
        return 2
    if out.exists():
        print("refused: --out already exists (a credential is never overwritten)", file=sys.stderr)
        return 2
    owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
    if not owner_url:
        print("NOVRSOC_MIGRATION_DATABASE_URL is required (schema owner)", file=sys.stderr)
        return 2
    with create_engine(owner_url).begin() as conn:
        org = conn.execute(text("SELECT id, kind, status FROM novrsoc.organizations WHERE slug = :s"), {"s": org_slug}).first()
        if org is None:
            print("refused: no organization with that slug", file=sys.stderr)
            return 2
        if kind in PLATFORM_ONLY_KINDS and org.kind != "platform":
            print(f"refused: a {kind} identity belongs to the platform organization", file=sys.stderr)
            return 2
        if org.status != "active":
            print(f"refused: the organization is {org.status}", file=sys.stderr)
            return 2
        ident, token = devseed.create_service_identity(conn, org.id, kind, name, scopes=scopes)
        conn.execute(text("""INSERT INTO novrsoc.audit_events (org_id, actor_type, actor_label, action, outcome, resource_type, resource_id)
                             VALUES (:o, 'system', 'app.cli', 'SERVICE_IDENTITY_ISSUED', 'success', 'service_identity', :i)"""),
                     {"o": org.id, "i": str(ident)})
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token + "\n")
    print(f"issued {kind} identity {ident} for {org_slug}; credential written to {out} (shown nowhere else)")
    return 0


def revoke_service_identity(ident: str) -> int:
    owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
    if not owner_url:
        print("NOVRSOC_MIGRATION_DATABASE_URL is required (schema owner)", file=sys.stderr)
        return 2
    with create_engine(owner_url).begin() as conn:
        r = conn.execute(text("""UPDATE novrsoc.service_identities SET status = 'revoked', revoked_at = now()
                                 WHERE id = CAST(:i AS uuid) AND status = 'active' RETURNING org_id"""), {"i": ident}).first()
        if r is None:
            print("nothing revoked: unknown or already revoked identity", file=sys.stderr)
            return 1
        conn.execute(text("""INSERT INTO novrsoc.audit_events (org_id, actor_type, actor_label, action, outcome, resource_type, resource_id)
                             VALUES (:o, 'system', 'app.cli', 'SERVICE_IDENTITY_REVOKED', 'success', 'service_identity', :i)"""),
                     {"o": r.org_id, "i": ident})
    print(f"revoked {ident}")
    return 0


def backfill_rollback(ledger: Path, execute: bool) -> int:
    """Undo a historical backfill import from its ledger (backfill-ledger.jsonl, copied from Server 1). Removes ONLY
    alerts the import inserted: the ids the API classified as not yet stored just before each batch was sent
    (`new_ids`), received while the import ran, and untouched since (status still `new`, in no case). An alert that
    already existed (e.g. delivered by the live forwarder) was classified a duplicate and is never matched.
    Dry run unless --execute. Audited per organization."""
    owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
    if not owner_url:
        print("NOVRSOC_MIGRATION_DATABASE_URL is required (schema owner)", file=sys.stderr)
        return 2
    from datetime import datetime, timedelta
    ids, times, batches = set(), [], set()
    for line in ledger.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if not str(rec.get("batch_id", "")).startswith("bkf-"):
            print("refused: not a backfill ledger", file=sys.stderr)
            return 2
        if rec.get("kind") == "intent":
            ids.update(str(i) for i in rec.get("new_ids") or [])
            times.append(datetime.fromisoformat(rec["at"]))
            batches.add(rec["batch_id"])
    if not ids:
        print("the ledger lists no alert: nothing to roll back")
        return 0
    lo, hi = min(times) - timedelta(minutes=1), max(times) + timedelta(hours=1)   # inserted after its intent line
    with create_engine(owner_url).begin() as conn:
        rows = conn.execute(text("""
            SELECT a.id, a.org_id, a.status, a.log_source_id,
                   EXISTS (SELECT 1 FROM novrsoc.case_alerts ca WHERE ca.alert_id = a.id) AS in_case
              FROM novrsoc.alerts a
             WHERE a.source = 'wazuh' AND a.external_id = ANY(:ids) AND a.received_at BETWEEN :lo AND :hi"""),
            {"ids": sorted(ids), "lo": lo, "hi": hi}).all()
        removable = [r for r in rows if r.status == "new" and not r.in_case]
        kept = [r for r in rows if r not in removable]
        per_org: dict = {}
        for r in removable:
            per_org[str(r.org_id)] = per_org.get(str(r.org_id), 0) + 1
        summary = {"ledger_alert_ids": len(ids), "batches": len(batches), "inserted_by_the_import": len(rows),
                   "removable": len(removable), "kept_worked_on": len(kept), "by_organization": per_org, "executed": execute}
        if execute and removable:
            gone = [r.id for r in removable]
            per_src: dict = {}
            for r in removable:
                if r.log_source_id:
                    per_src[r.log_source_id] = per_src.get(r.log_source_id, 0) + 1
            conn.execute(text("DELETE FROM novrsoc.alerts WHERE id = ANY(:ids) AND status = 'new'"), {"ids": gone})
            for src, n in per_src.items():
                conn.execute(text("UPDATE novrsoc.log_sources SET event_count = GREATEST(event_count - :n, 0) WHERE id = :s"),
                             {"n": n, "s": src})
            for org, n in per_org.items():
                conn.execute(text("""INSERT INTO novrsoc.audit_events (org_id, actor_type, actor_label, action, outcome, resource_type,
                                                                      resource_id, details)
                                     VALUES (:o, 'system', 'app.cli', 'BACKFILL_ROLLED_BACK', 'success', 'backfill', :r, CAST(:d AS jsonb))"""),
                             {"o": org, "r": ledger.name[:200], "d": json.dumps({"removed": n, "batches": len(batches)})})
    print(json.dumps(summary, indent=2))
    if not execute:
        print("dry run: nothing removed. Re-run with --execute to remove the 'removable' alerts.")
    return 0


def attribution_audit(days: int) -> int:
    """READ-ONLY report of how alerts are attributed, and of every inconsistency, BEFORE any mapping is changed:
    group mappings (collection groups such as `default` flagged: ignored for attribution from release 0018), active
    client organizations with no mapping and no source, agents whose recent alerts carry only collection groups (their
    alerts would be quarantined after the upgrade, with the organization that currently receives them), agent ids seen
    under more than one organization, registered log sources, and quarantine by reason. Changes nothing (READ ONLY
    transaction). Run on Server 2:  docker compose run --rm migrate python -m app.cli attribution-audit --days 7"""
    owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
    if not owner_url:
        print("NOVRSOC_MIGRATION_DATABASE_URL is required (schema owner)", file=sys.stderr)
        return 2
    settings = Settings()  # type: ignore[call-arg]
    coll = sorted(settings.collection_groups)
    eng = create_engine(owner_url)
    since = {"d": f"{int(days)} days"}
    with eng.connect() as c:
        c.execute(text("SET TRANSACTION READ ONLY"))
        orgs = {r.id: r for r in c.execute(text("SELECT id, slug::text AS slug, kind, status FROM novrsoc.organizations"))}
        maps = c.execute(text("SELECT org_id, group_name FROM novrsoc.wazuh_group_mappings ORDER BY group_name")).all()
        srcs = c.execute(text("""SELECT org_id, name, kind, match_value, enabled, retired_at IS NOT NULL AS retired, event_count, last_event_at
                                 FROM novrsoc.log_sources ORDER BY org_id, name""")).all()
        only_coll = c.execute(text("""SELECT org_id, agent_id, max(agent_name) AS agent_name, agent_groups, count(*) AS alerts
                                      FROM novrsoc.alerts WHERE observed_at > now() - CAST(:d AS interval)
                                        AND agent_id <> '000' AND agent_groups <@ CAST(:g AS text[])
                                      GROUP BY org_id, agent_id, agent_groups ORDER BY alerts DESC LIMIT 500"""), {**since, "g": coll}).all()
        multi = c.execute(text("""SELECT agent_id, array_agg(DISTINCT org_id::text) AS orgs, count(*) AS alerts FROM novrsoc.alerts
                                  WHERE observed_at > now() - CAST(:d AS interval) AND agent_id <> '000'
                                  GROUP BY agent_id HAVING count(DISTINCT org_id) > 1 LIMIT 200"""), since).all()
        by_org_groups = c.execute(text("""SELECT org_id, agent_groups, count(DISTINCT agent_id) AS agents, count(*) AS alerts
                                          FROM novrsoc.alerts WHERE observed_at > now() - CAST(:d AS interval)
                                          GROUP BY org_id, agent_groups ORDER BY org_id, alerts DESC"""), since).all()
        quarantine = c.execute(text("""SELECT reason, count(*) AS n FROM novrsoc.alert_quarantine
                                       WHERE received_at > now() - CAST(:d AS interval) GROUP BY reason ORDER BY reason"""), since).all()
    slug = lambda o: orgs[o].slug if o in orgs else str(o)  # noqa: E731
    issues = []
    for m in maps:
        if m.group_name in settings.collection_groups:
            issues.append({"issue": "collection_group_mapped", "organization": slug(m.org_id), "group": m.group_name,
                           "effect": "ignored for attribution: agents that carry only this group are quarantined, never given "
                                     "to this organization; remove the mapping once its agents are in a group of their own"})
    mapped_orgs = {m.org_id for m in maps if m.group_name not in settings.collection_groups}
    sourced = {s.org_id for s in srcs if s.retired is False}
    for o in orgs.values():
        if o.kind == "client" and o.status == "active" and o.id not in mapped_orgs and o.id not in sourced:
            issues.append({"issue": "organization_without_attribution", "organization": o.slug,
                           "effect": "no endpoint group (other than a collection group) and no log source: it receives no alerts"})
    for r in only_coll:
        issues.append({"issue": "agent_only_in_collection_groups", "organization_now": slug(r.org_id), "agent_id": r.agent_id,
                       "agent_name": r.agent_name, "groups": list(r.agent_groups), f"alerts_last_{days}d": r.alerts,
                       "effect": "after the upgrade its alerts are quarantined (collection_group_only) until the agent is put "
                                 "in its organization's own group"})
    for r in multi:
        issues.append({"issue": "agent_id_in_several_organizations", "agent_id": r.agent_id, "organizations": [slug(uuid.UUID(o)) for o in r.orgs], f"alerts_last_{days}d": r.alerts,
                       "effect": "the agent moved between groups, or an agent id was reused; check the history before backfilling"})
    report = {
        "read_only": True, "window_days": days, "collection_groups": coll, "manager_events": settings.manager_events,
        "mappings": [{"organization": slug(m.org_id), "group": m.group_name, "collection_group": m.group_name in settings.collection_groups}
                     for m in maps],
        "log_sources": [{"organization": slug(s.org_id), "name": s.name, "kind": s.kind, "match_value": s.match_value,
                         "enabled": s.enabled, "retired": s.retired, "event_count": s.event_count,
                         "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None} for s in srcs],
        "alerts_by_organization_and_groups": [{"organization": slug(r.org_id), "groups": list(r.agent_groups), "agents": r.agents,
                                               "alerts": r.alerts} for r in by_org_groups],
        "quarantine_by_reason": {r.reason: r.n for r in quarantine},
        "inconsistencies": issues,
    }
    print(json.dumps(report, indent=2, default=str))
    return 0


def soar_bridge_tenant(org_slug: str) -> int:
    """READ-ONLY: print the `tenants` entry of the Server 1 bridge configuration (bridge.json) for ONE organization,
    derived from that organization's SOAR response policy, so the bridge's independent authorization matches what the
    organization approved. Only its own mapped Wazuh groups are listed (never a collection group). The operator reviews the
    entry and adds it to /etc/novrsoc-bridge/bridge.json on Server 1; the bridge keeps adapter=simulated and
    allow_live=false until live response is separately authorized."""
    owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
    if not owner_url:
        print("NOVRSOC_MIGRATION_DATABASE_URL is required (schema owner)", file=sys.stderr)
        return 2
    settings = Settings()  # type: ignore[call-arg]
    bridge_actions = {"block_ip", "isolate_agent", "disable_account"}
    with create_engine(owner_url).connect() as c:
        c.execute(text("SET TRANSACTION READ ONLY"))
        org = c.execute(text("SELECT id, status, kind FROM novrsoc.organizations WHERE slug = :s"), {"s": org_slug}).first()
        if org is None:
            print(f"unknown organization {org_slug}", file=sys.stderr)
            return 2
        pol = c.execute(text("SELECT * FROM novrsoc.soar_policies WHERE org_id = :o"), {"o": org.id}).first()
        mapped = {r[0] for r in c.execute(text("SELECT group_name FROM novrsoc.wazuh_group_mappings WHERE org_id = :o"), {"o": org.id})}
    if pol is None or not pol.allowed_actions:
        print(f"{org_slug} has no SOAR response policy with allowed actions: nothing to authorize on the bridge", file=sys.stderr)
        return 1
    groups = sorted(g for g in pol.allowed_agent_groups if g in mapped and g not in settings.collection_groups)
    dropped = sorted(set(pol.allowed_agent_groups) - set(groups))
    actions = sorted(a for a in pol.allowed_actions if a in bridge_actions)
    entry = {str(org.id): {"actions": actions, "agent_groups": groups}}
    notes = []
    if dropped:
        notes.append(f"left out (not this organization's mapped groups, or collection groups): {', '.join(dropped)}")
    if org.status != "active":
        notes.append(f"the organization is {org.status}: do not authorize it")
    if pol.emergency_stop:
        notes.append("the organization's SOAR emergency stop is ON")
    if any(a != "block_ip" for a in actions):
        notes.append("agent-targeted actions also need the adapter to look up the agent's groups on the manager (bridge: adapter)")
    print(json.dumps({"organization": org_slug, "tenants_entry": entry, "notes": notes,
                      "bridge_must_keep": {"adapter": "simulated", "allow_live": False}}, indent=2))
    return 0


def check_env() -> int:
    """Validate the environment before the API starts: settings, database (as the API role), migration head, and the
    configured adapters. Prints one line per check; exits 1 when any check fails. Never prints secret values."""
    from app.main import expected_migration_head
    problems, lines = 0, []

    def report(ok: bool, name: str, detail: str) -> None:
        nonlocal problems
        problems += 0 if ok else 1
        lines.append(f"{'OK  ' if ok else 'FAIL'} {name:<22} {detail}")
    try:
        settings = Settings()  # type: ignore[call-arg]
        report(True, "settings", f"env={settings.env} wazuh={settings.wazuh_mode} nhai={settings.nhai_backend} "
                                 f"vms={settings.vms_scanning} brand={settings.brand_resolver}")
    except Exception as e:  # ConfigError messages name settings only
        print(f"FAIL settings               {str(e)[:300]}")
        return 1
    try:
        with create_engine(settings.database_url.get_secret_value()).connect() as c:
            rev = c.execute(text("SELECT version_num FROM novrsoc.alembic_version")).scalar()
        head = expected_migration_head()
        report(rev == head, "database", f"reachable; migration {rev} (expected {head})")
    except Exception as e:
        report(False, "database", f"not reachable or not migrated ({type(e).__name__})")
    if settings.soar_bridge_url:
        try:
            key = Path(settings.soar_bridge_key_file).read_bytes().strip()
            report(len(key) >= 32, "soar bridge key", f"{len(key)} bytes (>= 32 required)")
        except OSError:
            report(False, "soar bridge key", "NOVRSOC_SOAR_BRIDGE_KEY_FILE cannot be read")
        url_ok = settings.soar_bridge_url.startswith("https://") or settings.soar_bridge_url.startswith("http://127.0.0.1")
        report(url_ok, "soar bridge url", "https, or http on loopback only")
    else:
        report(True, "soar bridge", "not configured: consequential steps fail honestly, nothing executes")
    if settings.env == "production":
        report(settings.wazuh_mode != "local_fixture" and settings.nhai_backend != "test_adapter", "production adapters",
               "no fixture or test adapter in production")
    print("\n".join(lines))
    return 1 if problems else 0


def _from_env_file(key: str) -> str | None:
    env = Path(__file__).resolve().parents[1] / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    return None


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed-dev")
    s.add_argument("--out", required=True, type=Path)
    s.add_argument("--if-empty", action="store_true", help="succeed without changes when already seeded")
    sub.add_parser("seed-dev-fixtures", help="map dev Wazuh groups and ingest the labelled local fixture alerts")
    ci = sub.add_parser("create-service-identity", help="issue a machine credential (written once to --out)")
    ci.add_argument("--kind", required=True, help="one of " + ", ".join(SERVICE_KIND_SCOPES))
    ci.add_argument("--name", required=True)
    ci.add_argument("--org-slug", default="novrsoc-platform")
    ci.add_argument("--scope", action="append", default=[], help="defaults to the kind's own scope (e.g. ti_feeder: intel:ingest)")
    ci.add_argument("--out", required=True, type=Path)
    ri = sub.add_parser("revoke-service-identity", help="revoke a machine credential")
    ri.add_argument("--id", required=True)
    bk = sub.add_parser("backup", help="encrypted logical backup of the database (records the run)")
    bk.add_argument("--out-dir", required=True, type=Path)
    bk.add_argument("--key-file", required=True, type=Path)
    bk.add_argument("--target-label", default="local")
    rd = sub.add_parser("restore-drill", help="restore a backup into a disposable database and check it")
    rd.add_argument("--file", required=True, type=Path)
    rd.add_argument("--key-file", required=True, type=Path)
    bp = sub.add_parser("bootstrap-platform", help="first start: platform organization + first super_admin (once)")
    bp.add_argument("--email", required=True)
    bp.add_argument("--org-name", default="NovrSOC Platform")
    bp.add_argument("--out", required=True, type=Path)
    sub.add_parser("check-env", help="validate settings, database, migration head and adapters before starting")
    rb = sub.add_parser("backfill-rollback", help="undo a historical backfill import from its ledger (dry run unless --execute)")
    rb.add_argument("--ledger", required=True, type=Path)
    rb.add_argument("--execute", action="store_true")
    sb = sub.add_parser("soar-bridge-tenant", help="read-only: the bridge.json tenants entry derived from one organization's SOAR policy")
    sb.add_argument("--org", required=True, help="organization slug")
    aa = sub.add_parser("attribution-audit", help="read-only report of alert attribution and mapping inconsistencies")
    aa.add_argument("--days", type=int, default=7, choices=range(1, 91), metavar="1..90")
    args = ap.parse_args()
    if args.cmd == "soar-bridge-tenant":
        return soar_bridge_tenant(args.org)
    if args.cmd == "attribution-audit":
        return attribution_audit(args.days)
    if args.cmd == "backfill-rollback":
        return backfill_rollback(args.ledger, args.execute)
    if args.cmd == "check-env":
        return check_env()
    if args.cmd == "bootstrap-platform":
        return bootstrap_platform(args.email, args.org_name, args.out)
    if args.cmd in ("backup", "restore-drill"):
        from app import backup
        owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
        if not owner_url:
            print("NOVRSOC_MIGRATION_DATABASE_URL is required (schema owner)", file=sys.stderr)
            return 2
        key = backup.load_key(args.key_file)
        if args.cmd == "backup":
            print(json.dumps(backup.run_backup(owner_url, args.out_dir, key, args.target_label)))
        else:
            admin_url = os.environ.get("NOVRSOC_TEST_ADMIN_DATABASE_URL") or _from_env_file("NOVRSOC_TEST_ADMIN_DATABASE_URL")
            print(json.dumps(backup.run_restore_drill(owner_url, admin_url, args.file, key)))
        return 0
    if args.cmd == "create-service-identity":
        return create_service_identity(args.kind, args.name, args.org_slug, args.scope, args.out)
    if args.cmd == "revoke-service-identity":
        return revoke_service_identity(args.id)
    if args.cmd == "seed-dev-fixtures":
        return seed_dev_fixtures()
    if args.cmd == "seed-dev":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        return seed_dev(args.out, args.if_empty)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
