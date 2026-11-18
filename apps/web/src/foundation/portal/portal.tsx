'use client';

// Which address this page was opened at: the NovrSOC platform, or one organization's portal (<name>.<base domain>).
// The API answers from the request host (GET /api/v1/portal, public). The host only chooses the branding shown here;
// what a person may see is decided by the API on every request, never by this module.
import { useEffect, useState, type CSSProperties } from 'react';
import { Logo } from '@/components/shared/Logo';
import { request, type Schemas } from '@/foundation/api/client';
import { ApiError } from '@/foundation/api/errors';

export type PortalInfo = Schemas['PortalInfo'];
// unknown: the API says there is no portal at this address (404). unavailable: the API could not answer (sign-in still
// shows its form, which then reports the service as unreachable).
export type PortalState = { status: 'loading' } | { status: 'ready'; portal: PortalInfo } | { status: 'unknown' } | { status: 'unavailable' };

let cached: Promise<PortalState> | null = null;

export function loadPortal(): Promise<PortalState> {
    cached ??= request<PortalInfo>('/api/v1/portal')
        .then((portal): PortalState => ({ status: 'ready', portal }))
        .catch((e): PortalState => {
            cached = null;                                      // ask again next time: the API may be back
            return e instanceof ApiError && e.status === 404 ? { status: 'unknown' } : { status: 'unavailable' };
        });
    return cached;
}

export function usePortal(): PortalState {
    const [state, setState] = useState<PortalState>({ status: 'loading' });
    useEffect(() => {
        let live = true;
        void loadPortal().then((s) => { if (live) setState(s); });
        return () => { live = false; };
    }, []);
    return state;
}

/** CSS custom properties for an organization's colors (falls back to the NovrSOC theme). */
export function brandStyle(p: PortalInfo | null | undefined): CSSProperties {
    const b = p?.branding;
    if (!b?.primary_color) return {};
    return { '--brand-primary': b.primary_color, '--brand-on-primary': b.text_on_primary,
             '--brand-secondary': b.secondary_color ?? b.primary_color } as CSSProperties;
}

/** Applies an organization portal's APPROVED theme and name to the whole document (html element: dialogs included), and
 *  restores the NovrSOC theme when the component unmounts. Nothing happens on the platform address. */
export function usePortalTheme(state: PortalState): void {
    const portal = state.status === 'ready' ? state.portal : null;
    const theme = portal?.kind === 'tenant' ? portal.branding?.theme ?? null : null;
    const name = portal?.kind === 'tenant' ? portal.branding?.display_name ?? null : null;
    useEffect(() => {
        const root = document.documentElement;
        const vars: [string, string][] = theme ? [['--portal-primary', theme.primary], ['--portal-primary-hover', theme.primary_hover],
            ['--portal-primary-fill', theme.primary_fill], ['--portal-tint-light', theme.tint_light], ['--portal-tint-dark', theme.tint_dark]] : [];
        for (const [k, v] of vars) root.style.setProperty(k, v);
        if (theme) root.classList.add('portal-themed');
        const title = document.title;
        if (name) document.title = `${name} · Security portal`;
        return () => {
            for (const [k] of vars) root.style.removeProperty(k);
            root.classList.remove('portal-themed');
            if (name) document.title = title;
        };
    }, [theme, name]);
}

/** The organization's logo and name on its portal; the NovrSOC logo elsewhere. */
export function BrandMark({ portal, size = 'md' }: { portal: PortalInfo | null | undefined; size?: 'sm' | 'md' | 'lg' }) {
    const b = portal?.kind === 'tenant' ? portal.branding : null;
    if (!b) return <Logo size={size} />;
    const h = size === 'lg' ? 'h-12' : size === 'md' ? 'h-9' : 'h-7';
    return (
        <span className="inline-flex items-center gap-2 min-w-0" data-testid="portal-brand">
            {/* eslint-disable-next-line @next/next/no-img-element -- a same-origin, digest-versioned raster logo */}
            {b.logo_url && <img src={b.logo_url} alt="" className={`${h} w-auto max-w-[9rem] object-contain`} />}
            <span className={`font-black text-foreground truncate ${size === 'lg' ? 'text-lg' : 'text-sm'}`}>{b.display_name}</span>
        </span>
    );
}
