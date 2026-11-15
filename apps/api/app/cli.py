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
from pathlib import Path

from sqlalchemy import create_engine, text

from app import devseed
from app.core.config import LOOPBACK_HOSTS, Settings


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


KINDS = ("forwarder", "vms_worker", "collector", "email_gateway", "backup_agent")


def create_service_identity(kind: str, name: str, org_slug: str, scopes: list[str], out: Path) -> int:
    """Issue one machine credential (nsk_). The secret is written ONCE to `out` (mode 0600) and never printed.
    Works in any environment: it is the operator tool for issuing forwarder / worker credentials."""
    if kind not in KINDS:
        print(f"refused: --kind must be one of {', '.join(KINDS)}", file=sys.stderr)
        return 2
    if out.exists():
        print("refused: --out already exists (a credential is never overwritten)", file=sys.stderr)
        return 2
    owner_url = os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL") or _from_env_file("NOVRSOC_MIGRATION_DATABASE_URL")
    if not owner_url:
        print("NOVRSOC_MIGRATION_DATABASE_URL is required (schema owner)", file=sys.stderr)
        return 2
    with create_engine(owner_url).begin() as conn:
        org = conn.execute(text("SELECT id, kind FROM novrsoc.organizations WHERE slug = :s"), {"s": org_slug}).first()
        if org is None:
            print("refused: no organization with that slug", file=sys.stderr)
            return 2
        if kind == "forwarder" and org.kind != "platform":
            print("refused: a forwarder identity belongs to the platform organization", file=sys.stderr)
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
    ci.add_argument("--kind", required=True)
    ci.add_argument("--name", required=True)
    ci.add_argument("--org-slug", default="novrsoc-platform")
    ci.add_argument("--scope", action="append", default=[])
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
    args = ap.parse_args()
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
