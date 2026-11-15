// V2 API client. Same-origin calls to /api/v1 (proxied to FastAPI by next.config.ts), cookie session,
// CSRF header on unsafe methods, active organization via X-Org-Id. Every path is checked at compile
// time against the generated OpenAPI types, so API drift breaks `npm run typecheck`.
import type { components, paths } from './schema.gen';
import { ApiError, apiErrorFromResponse } from './errors';

export type Schemas = components['schemas'];
export type SessionInfo = Schemas['SessionInfo'];
export type OrgSummary = Schemas['OrgSummary'];
export type Site = Schemas['Site'];
export type SiteCreate = Schemas['SiteCreate'];

const P = {
    login: '/api/v1/auth/login',
    logout: '/api/v1/auth/logout',
    me: '/api/v1/auth/me',
    password: '/api/v1/auth/password',
    orgs: '/api/v1/orgs',
    sites: '/api/v1/sites',
    site: '/api/v1/sites/{site_id}',
} as const satisfies Record<string, keyof paths>;

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
export const CSRF_COOKIE = 'novrsoc_csrf';

function readCookie(name: string): string | null {
    if (typeof document === 'undefined') return null;
    const hit = document.cookie.split('; ').find((c) => c.startsWith(`${name}=`));
    return hit ? decodeURIComponent(hit.slice(name.length + 1)) : null;
}

export interface RequestOptions { method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'; body?: unknown; orgId?: string | null; signal?: AbortSignal }

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    const method = opts.method ?? 'GET';
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    if (opts.orgId) headers['X-Org-Id'] = opts.orgId;
    if (UNSAFE.has(method)) { const csrf = readCookie(CSRF_COOKIE); if (csrf) headers['X-CSRF-Token'] = csrf; }
    let res: Response;
    try {
        res = await fetch(path, { method, headers, credentials: 'same-origin', cache: 'no-store', signal: opts.signal,
            body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
    } catch (e) {
        if ((e as Error).name === 'AbortError') throw e;
        throw new ApiError(0, 'backend_unreachable', 'The NovrSOC service could not be reached.');
    }
    if (!res.ok) throw await apiErrorFromResponse(res);
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
}

const sitePath = (id: string) => P.site.replace('{site_id}', encodeURIComponent(id));

export const api = {
    login: (email: string, password: string) =>
        request<Schemas['LoginResponse']>(P.login, { method: 'POST', body: { email, password } satisfies Schemas['LoginRequest'] }),
    logout: () => request<void>(P.logout, { method: 'POST' }),
    changePassword: (body: Schemas['PasswordChangeRequest']) => request<void>(P.password, { method: 'POST', body }),
    me: (orgId?: string | null, signal?: AbortSignal) => request<SessionInfo>(P.me, { orgId, signal }),
    orgs: (orgId?: string | null) => request<Schemas['OrgList']>(P.orgs, { orgId }),
    listSites: (orgId: string | null) => request<Schemas['SiteList']>(P.sites, { orgId }),
    getSite: (orgId: string | null, id: string) => request<Site>(sitePath(id), { orgId }),
    createSite: (orgId: string | null, body: SiteCreate) => request<Site>(P.sites, { method: 'POST', orgId, body }),
};
