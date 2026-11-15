# syntax=docker/dockerfile:1
# NovrSOC V2 web image: Next.js standalone server. The browser talks only to this origin; /api/v1/* is rewritten to
# the API service, and that origin is compiled into the build (NOVRSOC_API_ORIGIN, default the compose service name).
# Build context: repository root.   docker build -f deploy/docker/web.Dockerfile -t novrsoc-web:<git sha> .
FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS build
ENV NEXT_TELEMETRY_DISABLED=1 NOVRSOC_NEXT_OUTPUT=standalone
WORKDIR /build
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
ARG NOVRSOC_API_ORIGIN=http://api:8000
ENV NOVRSOC_API_ORIGIN=${NOVRSOC_API_ORIGIN}
RUN npx next build

FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3210
WORKDIR /srv/web
# The image's built-in "node" user (uid 1000): no root at run time.
COPY --from=build --chown=node:node /build/.next/standalone ./
COPY --from=build --chown=node:node /build/.next/static ./.next/static
COPY --from=build --chown=node:node /build/public ./public
ARG NOVRSOC_GIT_SHA=unknown
LABEL org.opencontainers.image.title="novrsoc-web" org.opencontainers.image.revision="${NOVRSOC_GIT_SHA}" \
      org.opencontainers.image.description="NovrSOC V2 web application (Next.js standalone)"
USER node
EXPOSE 3210
CMD ["node", "server.js"]
