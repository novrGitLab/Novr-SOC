// Helpers for module API files (src/app/(app)/app/<module>/api.ts). Module files declare their paths with
// `satisfies Record<string, ApiPath>`, so a path that is not in the generated OpenAPI breaks the typecheck.
import type { paths } from './schema.gen';

export type ApiPath = keyof paths;

/** Fills `{name}` placeholders of an OpenAPI path, URL-encoding each value. */
export const fillPath = (path: ApiPath, values: Record<string, string>) =>
    path.replace(/\{(\w+)\}/g, (_, k: string) => encodeURIComponent(values[k] ?? ''));

/** A query string from the defined, non-empty values (or ''). */
export const queryString = (params: Record<string, string | number | undefined | null>) => {
    const u = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.set(k, String(v));
    const s = u.toString();
    return s ? `?${s}` : '';
};

/** A fresh idempotency key for one user action (contract pattern: 16-128 of [A-Za-z0-9._:-]). */
export function newIdempotencyKey(prefix: string): string {
    const rand = typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    return `${prefix}-${rand}`.replace(/[^A-Za-z0-9._:-]/g, '');
}
