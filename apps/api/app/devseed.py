"""Development and test data helpers. They use the SCHEMA-OWNER connection (bypasses RLS as owner)
and are never imported by request handling. The CLI refuses anything but a development/test loopback DB."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.core.security import hash_password, new_machine_credential


def create_org(conn: Connection, slug: str, name: str, kind: str = "client") -> uuid.UUID:
    return conn.execute(text("INSERT INTO novrsoc.organizations (slug, name, kind) VALUES (:s, :n, :k) RETURNING id"),
                        {"s": slug, "n": name, "k": kind}).scalar_one()


def create_user(conn: Connection, email: str, password: str | None, role: str, home_org: uuid.UUID,
                assignments: dict[uuid.UUID, str] | None = None, display_name: str = "") -> uuid.UUID:
    uid = conn.execute(text("INSERT INTO novrsoc.users (email, display_name, password_hash) VALUES (:e, :d, :p) RETURNING id"),
                       {"e": email, "d": display_name or email.split("@")[0],
                        "p": hash_password(password) if password else None}).scalar_one()
    conn.execute(text("INSERT INTO novrsoc.memberships (user_id, org_id, role_key, access_scope) VALUES (:u, :o, :r, 'home')"),
                 {"u": uid, "o": home_org, "r": role})
    for org, scope in (assignments or {}).items():
        conn.execute(text("INSERT INTO novrsoc.memberships (user_id, org_id, role_key, access_scope) VALUES (:u, :o, :r, :s)"),
                     {"u": uid, "o": org, "r": role, "s": scope})
    return uid


def create_site(conn: Connection, org: uuid.UUID, name: str, cidrs: list[str] | None = None) -> uuid.UUID:
    return conn.execute(text("INSERT INTO novrsoc.sites (org_id, name, network_cidrs) VALUES (:o, :n, CAST(:c AS cidr[])) RETURNING id"),
                        {"o": org, "n": name, "c": cidrs or []}).scalar_one()


def create_service_identity(conn: Connection, org: uuid.UUID, kind: str, name: str, site: uuid.UUID | None = None,
                            scopes: list[str] | None = None) -> tuple[uuid.UUID, str]:
    ident = uuid.uuid4()
    token, secret_hash = new_machine_credential(ident)
    conn.execute(text("""INSERT INTO novrsoc.service_identities (id, org_id, site_id, kind, name, secret_hash, scopes)
                         VALUES (:i, :o, :s, :k, :n, :h, :sc)"""),
                 {"i": ident, "o": org, "s": site, "k": kind, "n": name, "h": secret_hash, "sc": scopes or []})
    return ident, token


def revoke_service_identity(conn: Connection, ident: uuid.UUID) -> None:
    conn.execute(text("UPDATE novrsoc.service_identities SET status = 'revoked', revoked_at = now() WHERE id = :i"), {"i": ident})


def grant_cnii(conn: Connection, user: uuid.UUID, sectors: list[str], granted_by: uuid.UUID | None,
               days: int = 30, scope_org_ids: list[uuid.UUID] | None = None) -> uuid.UUID:
    return conn.execute(text("""INSERT INTO novrsoc.cnii_designations (user_id, sectors, scope_org_ids, reason, granted_by, expires_at)
                                VALUES (:u, :s, :o, 'development seed', :g, :x) RETURNING id"""),
                        {"u": user, "s": sectors, "o": scope_org_ids, "g": granted_by,
                         "x": datetime.now(timezone.utc) + timedelta(days=days)}).scalar_one()
