"""CNII access: a normal permission is necessary but NOT sufficient. The caller must also hold an
explicit, unexpired, unrevoked designation covering the sector. Organization membership and staff
roles never grant CNII access on their own (owner requirement; replaces legacy cnii:sector-only checks)."""
from __future__ import annotations

from dataclasses import dataclass
import uuid

from fastapi import Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import service as audit
from app.auth.deps import Principal, client_ip, current_principal
from app.core.errors import forbidden
from app.db.session import request_connection

# The 13 sector ids of legacy lib/cnii-sectors.ts, kept identical so existing CNII data maps 1:1.
CNII_SECTORS = ("power", "water", "ict", "finance", "health", "publicadmin", "education", "defence",
                "transport", "food", "safety", "industrial", "mines")


@dataclass(frozen=True)
class Designation:
    id: uuid.UUID
    sector: str
    sectors: tuple[str, ...]
    scope_org_ids: tuple[uuid.UUID, ...] | None


def require_cnii(permission: str = "cnii:read"):
    def dep(request: Request, sector: str = Query(..., pattern="^[a-z_]{3,40}$"),
            p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> Designation:
        def deny(reason: str):
            audit.record("CNII_ACCESS_DENIED", "denied", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                         resource_type="cnii_sector", resource_id=sector, request_id=request.state.request_id,
                         ip=client_ip(request), details={"reason": reason, "permission": permission})
            return forbidden("CNII access requires the permission and an explicit CNII designation",
                             {"required": permission, "designation": "required"})
        if sector not in CNII_SECTORS:
            raise deny("unknown sector")
        if not p.has(permission):
            raise deny("missing permission")
        row = conn.execute(text("""
            SELECT id, sectors, scope_org_ids FROM novrsoc.cnii_designations
             WHERE user_id = novrsoc.app_user() AND revoked_at IS NULL AND expires_at > now()
               AND :sector = ANY(sectors)
             ORDER BY expires_at DESC LIMIT 1"""), {"sector": sector}).first()
        if not row:
            raise deny("no active designation for sector")
        if row.scope_org_ids is not None and p.org_id not in row.scope_org_ids:
            raise deny("designation does not cover the active organization")
        audit.record("CNII_ACCESS", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                     resource_type="cnii_sector", resource_id=sector, request_id=request.state.request_id,
                     ip=client_ip(request), details={"designation_id": str(row.id)})
        return Designation(row.id, sector, tuple(row.sectors), tuple(row.scope_org_ids) if row.scope_org_ids else None)
    return dep
