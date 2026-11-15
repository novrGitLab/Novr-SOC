"""AI activity and notifications, written in the CALLER's transaction (they commit or roll back with the action).

ai_activity is the record behind the SOAR activity centre: every AI analysis request, result, failure, recommendation,
proposed action, human review and NovrChat exchange. It is append-only (trigger) and never describes an execution:
response execution is recorded by the SOAR engine (soar_steps) and the audit log.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Iterable

from sqlalchemy import text
from sqlalchemy.engine import Connection


def ai(conn: Connection, kind: str, module: str, *, task: str = "", subject_type: str = "", subject_id: str = "",
       actor_type: str = "user", actor_id: uuid.UUID | None = None, actor_label: str = "", model: str = "",
       outcome: str = "success", summary: str = "", details: dict[str, Any] | None = None,
       nhai_job_id: uuid.UUID | None = None) -> None:
    conn.execute(text("""INSERT INTO novrsoc.ai_activity (org_id, kind, module, task, subject_type, subject_id, actor_type, actor_id,
                                                          actor_label, model, outcome, summary, details, nhai_job_id)
                         VALUES (novrsoc.app_org(), :k, :m, :t, :st, :si, :at, :ai, :al, :mo, :o, :s, CAST(:d AS jsonb), :j)"""),
                 {"k": kind, "m": module, "t": task, "st": subject_type, "si": str(subject_id)[:200], "at": actor_type, "ai": actor_id,
                  "al": actor_label[:200], "mo": model[:120], "o": outcome, "s": summary[:500], "d": json.dumps(details or {}, default=str),
                  "j": nhai_job_id})


def notify(conn: Connection, user_ids: Iterable[uuid.UUID], kind: str, title: str, body: str = "", link: str = "") -> int:
    n = 0
    for uid in dict.fromkeys(user_ids):
        conn.execute(text("""INSERT INTO novrsoc.notifications (org_id, user_id, kind, title, body, link)
                             VALUES (novrsoc.app_org(), :u, :k, :t, :b, :l)"""),
                     {"u": uid, "k": kind, "t": title[:200], "b": body[:2000], "l": link})
        n += 1
    return n


def users_with_roles(conn: Connection, roles: list[str]) -> list:
    return conn.execute(text("SELECT * FROM novrsoc.org_users_with_role(:r)"), {"r": roles}).all()
