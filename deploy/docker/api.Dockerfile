# syntax=docker/dockerfile:1
# NovrSOC V2 API image: FastAPI (with the SOAR engine, approvals and audit), Alembic migrations, operator CLI
# (check-env, bootstrap-platform, backup, restore-drill) and the NHAI worker (Server 1 runs it from this image).
# Build context: repository root.   docker build -f deploy/docker/api.Dockerfile -t novrsoc-api:<git sha> .
FROM python:3.12-slim@sha256:e695ab189fa2d082b1c61c69a6b888a5adeca61ceeccad107b1ed2a125721a9e

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# pg_dump / pg_restore must match the server's major version (PostgreSQL 16) for backups and restore drills:
# taken from the PostgreSQL project's apt repository (signed; the key is fetched over HTTPS).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    install -d /usr/share/postgresql-common/pgdg; \
    curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc; \
    . /etc/os-release; \
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends postgresql-client-16; \
    apt-get purge -y curl; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*; \
    pg_dump --version

RUN groupadd --system --gid 10001 novrsoc \
 && useradd --system --uid 10001 --gid novrsoc --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin novrsoc

WORKDIR /srv/novrsoc
# Exactly the tested versions (requirements.lock), runtime closure only: scripts/release/runtime_lock.py.
COPY apps/api/requirements.runtime.lock apps/api/requirements.runtime.lock
RUN pip install --no-deps -r apps/api/requirements.runtime.lock
COPY packages/contracts/pyproject.toml packages/contracts/README.md packages/contracts/
COPY packages/contracts/python packages/contracts/python
RUN pip install --no-deps ./packages/contracts && pip check
# The repository layout is kept: the API finds packages/db/alembic.ini relative to apps/api/app.
COPY packages/db packages/db
COPY apps/api/pyproject.toml apps/api/pyproject.toml
COPY apps/api/app apps/api/app
RUN python -m compileall -q apps/api/app packages/db/migrations

ARG NOVRSOC_GIT_SHA=unknown
LABEL org.opencontainers.image.title="novrsoc-api" org.opencontainers.image.revision="${NOVRSOC_GIT_SHA}" \
      org.opencontainers.image.description="NovrSOC V2 API, migrations, operator CLI and NHAI worker"
ENV NOVRSOC_GIT_SHA=${NOVRSOC_GIT_SHA}

USER novrsoc:novrsoc
WORKDIR /srv/novrsoc/apps/api
EXPOSE 8000
# Client addresses are taken from X-Forwarded-For only from FORWARDED_ALLOW_IPS (set in compose).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--no-server-header"]
