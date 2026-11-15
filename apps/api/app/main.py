"""NovrSOC V2 API — Phase 2 foundation.

Run (local, against the disposable database):
  cd apps/api && .venv/Scripts/uvicorn app.main:app --port 8000
"""
from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import Settings, get_settings
from app.core.errors import install_error_handlers
from app.db import session as db
from app.routers import auth, platform, tenant
from novrsoc_contracts.v1.common import CONTRACT_VERSION
from novrsoc_contracts.v1.platform import HealthResponse, ReadinessCheck, ReadinessResponse

API_VERSION = "1.0.0"
MIGRATIONS_INI = Path(__file__).resolve().parents[3] / "packages" / "db" / "alembic.ini"


def expected_migration_head() -> str | None:
    """The single Alembic head shipped with this build (readiness compares the database against it).
    Derived from the migration scripts, so adding a migration never requires editing this file."""
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        heads = ScriptDirectory.from_config(Config(str(MIGRATIONS_INI))).get_heads()
        return heads[0] if len(heads) == 1 else None
    except Exception:
        return None
_REQ_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    db.init_engine(settings.database_url.get_secret_value())
    app = FastAPI(
        title="NovrSOC API", version=API_VERSION,
        summary="NovrSOC V2 API. Phase 2 foundation: authentication, tenancy, permissions, audit, sites.",
        docs_url="/api/docs" if settings.docs_enabled else None, redoc_url=None,
        openapi_url="/api/openapi.json" if settings.docs_enabled else None,
    )
    app.dependency_overrides[get_settings] = lambda: settings
    install_error_handlers(app)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("X-Request-Id", "")
        request.state.request_id = incoming if _REQ_ID.match(incoming) else uuid.uuid4().hex
        response: Response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        response.headers["X-API-Version"] = API_VERSION
        response.headers["X-Contract-Version"] = CONTRACT_VERSION
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/healthz", response_model=HealthResponse, tags=["health"], summary="Liveness (no dependencies)")
    def healthz() -> HealthResponse:
        return HealthResponse(status="ok", service=settings.service_name, version=API_VERSION)

    @app.get("/readyz", response_model=ReadinessResponse, tags=["health"],
             summary="Readiness: database reachable and at the expected migration",
             responses={503: {"model": ReadinessResponse}})
    def readyz():
        checks: list[ReadinessCheck] = []
        try:
            with db.engine().connect() as conn:
                conn.execute(text("SELECT 1"))
                checks.append(ReadinessCheck(name="database", ok=True))
                rev = conn.execute(text("SELECT version_num FROM novrsoc.alembic_version")).scalar()
                head = expected_migration_head()
                checks.append(ReadinessCheck(name="migrations", ok=head is not None and rev == head,
                                             detail=f"at {rev}, expected {head or 'a single head (none or several found)'}"))
        except Exception as exc:  # never echo connection strings
            checks.append(ReadinessCheck(name="database", ok=False, detail=type(exc).__name__))
        ready = all(c.ok for c in checks) and len(checks) == 2
        body = ReadinessResponse(status="ready" if ready else "not_ready", checks=checks)
        return JSONResponse(body.model_dump(), status_code=200 if ready else 503)

    for r in (auth.router, auth.orgs_router, tenant.sites, tenant.audit_router, tenant.service, tenant.cnii, platform.router):
        app.include_router(r)
    # Workstream modules (app/modules/<name>/) are discovered and validated; see app/modules/__init__.py.
    from app.modules import discover
    for info, router in discover():
        app.include_router(router)
        app.state.modules = getattr(app.state, "modules", []) + [info]
    return app


_app: FastAPI | None = None


def __getattr__(name: str):  # `uvicorn app.main:app` builds the app on first access; tests build their own
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
