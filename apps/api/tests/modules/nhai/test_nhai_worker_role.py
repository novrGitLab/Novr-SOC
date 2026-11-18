"""The dedicated NHAI worker role (`novrsoc_nhai`, migration 0016): the worker completes EVERY consolidated task
(alert explanation, finding explanation, asset summary, NovrChat answer) under that role, and the role can do nothing
else: exact column grants, no other table, append-only writes, row-level security as for the API."""
import pytest
from psycopg import errors as pg
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import DBAPIError

from app.connectors.inference import TestInferenceAdapter
from app.db import session as db_session
from app.main import create_app
from tests.conftest import _with_db
from tests.modules.conftest import Client
from tests.modules.nhai.test_nhai import drain
from tests.modules.nhai.test_nhai_consolidation import alpha_finding  # noqa: F401  (fixture)

ROLE = "novrsoc_nhai"
EXPECTED = {
    ("nhai_jobs", "SELECT"): {"id", "org_id", "task", "subject_type", "subject_id", "requested_by", "status", "attempts",
                              "max_attempts", "worker_id", "bundle"},
    ("nhai_jobs", "UPDATE"): {"status", "error_code", "result", "finished_at", "lease_until", "worker_id"},
    ("alerts", "SELECT"): {"id", "org_id", "severity"},
    ("vms_findings", "SELECT"): {"id", "org_id", "severity"},
    ("assets", "SELECT"): {"id", "org_id"},
    ("cases", "SELECT"): {"id", "org_id"},                       # migration 0018: does the case still exist
    ("ai_activity", "INSERT"): {"org_id", "kind", "module", "task", "subject_type", "subject_id", "actor_type", "actor_id",
                                "actor_label", "model", "outcome", "summary", "details", "nhai_job_id"},
    ("audit_events", "INSERT"): {"org_id", "actor_type", "actor_id", "actor_label", "action", "outcome", "resource_type",
                                 "resource_id", "request_id", "ip", "details"},
}


@pytest.fixture(scope="module")
def nhai_role_engine(db):
    """Connections to the test database that act as novrsoc_nhai (SET ROLE from the cluster superuser: the role is
    NOLOGIN until gate G-F2). Every statement is then checked with the worker role's privileges and RLS."""
    eng = create_engine(_with_db(db.admin_url, db.name))

    @event.listens_for(eng, "connect")
    def _as_worker(dbapi_conn, _record):
        with dbapi_conn.cursor() as cur:
            cur.execute(f"SET SESSION ROLE {ROLE}")
        dbapi_conn.commit()

    yield eng
    eng.dispose()


def test_role_attributes_and_exact_grants(owner):
    with owner.connect() as c:
        r = c.execute(text("SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = :r"),
                      {"r": ROLE}).one()
        assert tuple(r) == (False, False, False, False, False)
        assert c.execute(text("""SELECT count(*) FROM information_schema.role_table_grants
                                 WHERE grantee = :r AND table_schema = 'novrsoc'"""), {"r": ROLE}).scalar() == 0  # no table-wide grant
        got: dict[tuple[str, str], set[str]] = {}
        for t, col, priv in c.execute(text("""SELECT table_name, column_name, privilege_type FROM information_schema.column_privileges
                                              WHERE grantee = :r AND table_schema = 'novrsoc'"""), {"r": ROLE}):
            got.setdefault((t, priv), set()).add(col)
        assert got == EXPECTED
        funcs = {f for (f,) in c.execute(text("""SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                                                 WHERE n.nspname = 'novrsoc' AND has_function_privilege(:r, p.oid, 'EXECUTE')"""), {"r": ROLE})}
        # nhai_heartbeat (migration 0021): writes ONLY the nhai_worker heartbeat row, for NHAI readiness
        assert funcs == {"app_org", "nhai_claim_job", "nhai_expire_jobs", "nhai_heartbeat"}


def test_worker_completes_every_consolidated_task_as_the_worker_role(fixture_settings, fixture_alerts, alpha_finding,  # noqa: F811
                                                                     nhai_role_engine, owner, world, monkeypatch):
    app = create_app(fixture_settings.model_copy(update={"nhai_backend": "test_adapter"}))
    a = Client(app, "analyst_a")
    alert_id = a.get("/api/v1/soc/alerts?limit=200").json()["items"][0]["id"]
    fid, asset = alpha_finding
    case = a.post("/api/v1/soc/cases", {"alert_ids": [alert_id], "title": "NHAI case assistance", "severity": "medium",
                                        "source_id": f"nhai-role-{alert_id}"}).json()
    jobs = [a.post("/api/v1/nhai/alert-explanations", {"alert_id": alert_id}).json(),
            a.post("/api/v1/nhai/finding-explanations", {"finding_id": str(fid)}).json(),
            a.post("/api/v1/nhai/asset-summaries", {"asset_id": str(asset)}).json(),
            a.post("/api/v1/nhai/case-assistance", {"case_id": case["case_id"]}).json()]
    conv = a.post("/api/v1/chat/conversations", {}).json()
    chat = a.post(f"/api/v1/chat/conversations/{conv['id']}/messages", {"content": "Which critical and high alerts came in this month?"})
    assert chat.status_code == 201, chat.text
    jobs.append(chat.json()["answer"]["nhai"])
    ids = {j["id"] for j in jobs if j and j.get("id")}
    assert len(ids) == 5, jobs
    # audit.record writes through the module engine: point it at the worker role too, as on Server 1
    monkeypatch.setattr(db_session, "_engine", nhai_role_engine)
    statuses = drain(nhai_role_engine, fixture_settings, TestInferenceAdapter())
    assert statuses and set(statuses) <= {"succeeded", "failed"}          # no permission error escaped the worker
    with owner.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        done = dict(c.execute(text("SELECT task, status FROM novrsoc.nhai_jobs WHERE id = ANY(CAST(:i AS uuid[]))"), {"i": list(ids)}).all())
        assert done == {"alert_explanation": "succeeded", "finding_explanation": "succeeded", "asset_summary": "succeeded",
                        "chat_answer": "succeeded", "investigation_assistance": "succeeded"}
        acts = c.execute(text("SELECT count(*) FROM novrsoc.ai_activity WHERE nhai_job_id = ANY(CAST(:i AS uuid[])) AND kind = 'analysis_completed'"),
                         {"i": list(ids)}).scalar()
        assert acts == 5
        audits = c.execute(text("""SELECT count(*) FROM novrsoc.audit_events WHERE action = 'NHAI_JOB_FINISHED'
                                   AND resource_id = ANY(:i)"""), {"i": list(ids)}).scalar()
        assert audits == 5


@pytest.mark.parametrize("sql", [
    "SELECT rule_description FROM novrsoc.alerts",               # only id, org_id, severity
    "SELECT * FROM novrsoc.users",
    "SELECT * FROM novrsoc.sessions",
    "SELECT * FROM novrsoc.service_identities",
    "SELECT title FROM novrsoc.cases",                          # only id, org_id
    "SELECT content FROM novrsoc.chat_messages",
    "SELECT summary FROM novrsoc.ai_activity",                  # append-only for the worker: write, never read
    "SELECT action FROM novrsoc.audit_events",
    "UPDATE novrsoc.nhai_jobs SET bundle = '{}'::jsonb",
    "UPDATE novrsoc.nhai_jobs SET review_decision = 'accept'",
    "UPDATE novrsoc.alerts SET severity = 'low'",
    "DELETE FROM novrsoc.nhai_jobs",
    "INSERT INTO novrsoc.notifications (org_id, user_id, kind, title) VALUES (novrsoc.app_org(), gen_random_uuid(), 'x', 'x')",
    "SELECT novrsoc.platform_analytics()",
])
def test_everything_else_is_refused(nhai_role_engine, world, sql):
    with pytest.raises(DBAPIError) as e, nhai_role_engine.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        c.execute(text(sql))
    assert isinstance(e.value.orig, pg.InsufficientPrivilege), e.value.orig


def test_row_level_security_applies_to_the_worker_role(nhai_role_engine, owner, world):
    # The schema owner is not subject to RLS (no FORCE): it gives the ground truth per organization.
    with owner.connect() as c:
        truth = {org: set(c.execute(text("SELECT id FROM novrsoc.nhai_jobs WHERE org_id = :o"), {"o": org}).scalars().all())
                 for org in (world.alpha, world.beta)}
    assert truth[world.alpha]
    with nhai_role_engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM novrsoc.nhai_jobs")).scalar() == 0              # no context: nothing
    for org in (world.alpha, world.beta):
        with nhai_role_engine.begin() as c:
            c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
            seen = set(c.execute(text("SELECT id FROM novrsoc.nhai_jobs")).scalars().all())
        assert seen == truth[org]                                                                   # its own jobs, no other
