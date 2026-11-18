# syntax=docker/dockerfile:1
# NovrSOC V2 VMS worker WITH the nmap_service engine's tool (nmap). Not built by default and not used by the compose file:
# a scanner runs only where an explicit deployment decision places it (a host with a route to the client network it scans,
# declared in VMS_ALLOWED_NETWORKS), and it scans only what the API hands out under the organization's enabled scan
# policy (NOVRSOC_VMS_SCANNING=authorized_scopes). VMS_ENGINE stays `disabled` until that decision sets it to nmap_service.
# nmap runs as the unprivileged user: -sT (TCP connect) and -sV need no raw sockets; no capability is added.
# Build context: repository root.   docker build -f deploy/docker/vms-scanner.Dockerfile -t novrsoc-vms-scanner:<git sha> .
FROM python:3.12-slim@sha256:e695ab189fa2d082b1c61c69a6b888a5adeca61ceeccad107b1ed2a125721a9e

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10002 novrsoc-vms \
 && useradd --system --uid 10002 --gid novrsoc-vms --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin novrsoc-vms

WORKDIR /srv/vms-worker
COPY services/vms-worker/requirements.lock requirements.lock
RUN pip install --no-deps -r requirements.lock && pip check
COPY services/vms-worker/v2_adapter.py services/vms-worker/worker.py ./
RUN python -m compileall -q . && nmap --version | head -1 && ! python -c "import gvm" 2>/dev/null

ARG NOVRSOC_GIT_SHA=unknown
LABEL org.opencontainers.image.title="novrsoc-vms-scanner" org.opencontainers.image.revision="${NOVRSOC_GIT_SHA}" \
      org.opencontainers.image.description="NovrSOC V2 VMS worker with nmap (nmap_service engine; disabled by default)"
ENV NOVRSOC_GIT_SHA=${NOVRSOC_GIT_SHA} VMS_ENGINE=disabled

USER novrsoc-vms:novrsoc-vms
CMD ["python", "v2_adapter.py"]
