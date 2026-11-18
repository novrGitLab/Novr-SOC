# syntax=docker/dockerfile:1
# NovrSOC V2 VMS worker image: Server 2, compose service `vms-worker` (profile "vms"), on an internal network that
# reaches only the API. Scanning is disabled by default (VMS_ENGINE=disabled: heartbeat only, no job is claimed), and
# the image carries no scanning tool (no nmap, nuclei, ProjectDiscovery tools or python-gvm).
# Build context: repository root.   docker build -f deploy/docker/vms-worker.Dockerfile -t novrsoc-vms-worker:<git sha> .
FROM python:3.12-slim@sha256:e695ab189fa2d082b1c61c69a6b888a5adeca61ceeccad107b1ed2a125721a9e

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10002 novrsoc-vms \
 && useradd --system --uid 10002 --gid novrsoc-vms --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin novrsoc-vms

WORKDIR /srv/vms-worker
COPY services/vms-worker/requirements.lock requirements.lock
RUN pip install --no-deps -r requirements.lock && pip check
COPY services/vms-worker/v2_adapter.py services/vms-worker/worker.py services/vms-worker/gmp.py ./
RUN python -m compileall -q . \
 && ! command -v nmap && ! python -c "import gvm" 2>/dev/null

ARG NOVRSOC_GIT_SHA=unknown
LABEL org.opencontainers.image.title="novrsoc-vms-worker" org.opencontainers.image.revision="${NOVRSOC_GIT_SHA}" \
      org.opencontainers.image.description="NovrSOC V2 VMS worker (scanning disabled by default)"
ENV NOVRSOC_GIT_SHA=${NOVRSOC_GIT_SHA} VMS_ENGINE=disabled

USER novrsoc-vms:novrsoc-vms
CMD ["python", "v2_adapter.py"]
