"""Presence and team (consolidation): who works the active organization, and who is online right now.

Online status comes ONLY from a heartbeat the web application sends while a NovrSOC tab is open and visible (every 60
seconds; migration 0022). A person is online when their heartbeat for this organization is under two minutes old.
Until any heartbeat exists for the organization, presence is reported as not tracked and the online count is unknown,
never assumed to be zero. Member counts come from memberships under the organization's row-level security.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.auth.deps import Principal, current_principal, require
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.chat import TeamPresence, TeamRoleCount

MODULE = ModuleInfo(name="presence", workstream="E", prefix="/api/v1/presence",
                    summary="Presence heartbeats from open NovrSOC tabs, and the active organization's team")
router = APIRouter(prefix="/api/v1/presence", tags=["presence"], responses=ERRORS)

ONLINE_MINUTES = 2
ROLE_ORDER = ["soc_manager", "analyst", "executive", "portal_user", "super_admin"]


@router.post("/heartbeat", status_code=204, summary="I am here: the signed-in person has this organization open (every 60 s)")
def heartbeat(p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> Response:
    conn.execute(text("""INSERT INTO novrsoc.user_presence (user_id, org_id) VALUES (:u, :o)
                         ON CONFLICT (user_id, org_id) DO UPDATE SET last_seen_at = now()"""), {"u": p.user_id, "o": p.org_id})
    return Response(status_code=204)


def team(conn: Connection) -> TeamPresence:
    """Members of the active organization (RLS) by role, and who is online from heartbeats."""
    rows = conn.execute(text(f"""
        SELECT m.role_key, m.access_scope,
               count(*) AS n,
               count(*) FILTER (WHERE pr.last_seen_at > now() - interval '{ONLINE_MINUTES} minutes') AS online
        FROM novrsoc.memberships m JOIN novrsoc.users u ON u.id = m.user_id AND u.status = 'active'
        LEFT JOIN novrsoc.user_presence pr ON pr.user_id = m.user_id AND pr.org_id = m.org_id
        WHERE m.org_id = novrsoc.app_org() AND m.access_scope IN ('home', 'operations')
        GROUP BY 1, 2""")).all()
    tracked = conn.execute(text("SELECT EXISTS (SELECT 1 FROM novrsoc.user_presence)")).scalar()
    roles: dict[str, list[int]] = {}
    for r in rows:
        x = roles.setdefault(r.role_key, [0, 0])
        x[0] += r.n
        x[1] += r.online
    by_role = [TeamRoleCount(role=k, members=v[0], online=v[1] if tracked else None)
               for k, v in sorted(roles.items(), key=lambda kv: ROLE_ORDER.index(kv[0]) if kv[0] in ROLE_ORDER else 99)]
    online = sum(r.online for r in rows) if tracked else None
    return TeamPresence(generated_at=datetime.now(timezone.utc), members=sum(r.n for r in rows if r.access_scope == "home"),
                        assigned_staff=sum(r.n for r in rows if r.access_scope == "operations"), by_role=by_role,
                        presence_tracked=bool(tracked), online=online, online_window_minutes=ONLINE_MINUTES)


@router.get("/team", response_model=TeamPresence, summary="The active organization's people by role, and who is online now")
def get_team(p: Principal = Depends(require("org:read")), conn: Connection = Depends(request_connection)) -> TeamPresence:
    return team(conn)
