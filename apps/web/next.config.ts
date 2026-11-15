import type { NextConfig } from "next";
import { PHASE_PRODUCTION_BUILD } from "next/constants";

// The browser only ever talks to this origin. /api/v1/* is proxied to the FastAPI service, so the
// session cookie is first-party and no CORS is needed. NOVRSOC_API_ORIGIN is required for a
// production BUILD (rewrites are compiled into the route manifest); there is deliberately no remote
// fallback host. Development defaults to the local API.
export default function config(phase: string): NextConfig {
  const fallback = phase === PHASE_PRODUCTION_BUILD ? "" : "http://127.0.0.1:8000";
  const apiOrigin = (process.env.NOVRSOC_API_ORIGIN ?? fallback).replace(/\/+$/, "");
  if (!/^https?:\/\/[^/]+$/.test(apiOrigin)) {
    throw new Error("NOVRSOC_API_ORIGIN must be set to the API origin (e.g. http://127.0.0.1:8000) for a production build");
  }
  return {
    // Container image only (deploy/docker/web.Dockerfile): a self-contained server without the full node_modules.
    // Local preview and the browser test keep `next start` (no standalone output).
    ...(process.env.NOVRSOC_NEXT_OUTPUT === "standalone" ? { output: "standalone" as const } : {}),
    poweredByHeader: false,
    // Do not let `next dev` write agent instruction files (AGENTS.md) into the repository.
    agentRules: false,
    async rewrites() {
      return [{ source: "/api/v1/:path*", destination: `${apiOrigin}/api/v1/:path*` }];
    },
    async headers() {
      return [
        {
          source: '/(.*)',
          headers: [
            { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
            { key: 'X-Frame-Options', value: 'DENY' },
            { key: 'X-Content-Type-Options', value: 'nosniff' },
            { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
            { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          ],
        },
      ];
    },
  };
}
