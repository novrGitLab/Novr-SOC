'use client';

// Session and organization context. The active organization is a UI preference (localStorage holds an
// id, never a token); the API re-validates it on every request and falls back to the home org.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { api, type OrgSummary, type SessionInfo } from '@/foundation/api/client';
import { ApiError, uiState, type UiState } from '@/foundation/api/errors';

const ORG_KEY = 'novrsoc.activeOrg';

interface SessionValue {
    session: SessionInfo;
    orgId: string;
    orgs: OrgSummary[];
    can: (permission: string) => boolean;
    switchOrg: (orgId: string) => void;
    signOut: () => Promise<void>;
    refresh: () => void;
}

const Ctx = createContext<SessionValue | null>(null);

export function useSession(): SessionValue {
    const v = useContext(Ctx);
    if (!v) throw new Error('useSession() outside <SessionProvider>');
    return v;
}

function storedOrg(): string | null {
    try { return window.localStorage.getItem(ORG_KEY); } catch { return null; }
}
function storeOrg(id: string | null) {
    try { if (id) window.localStorage.setItem(ORG_KEY, id); else window.localStorage.removeItem(ORG_KEY); } catch { /* private mode */ }
}

export function SessionProvider({ children, loading, failed }: {
    children: ReactNode;
    loading: ReactNode;
    failed: (state: UiState, retry: () => void) => ReactNode;
}) {
    const router = useRouter();
    const pathname = usePathname();
    const [session, setSession] = useState<SessionInfo | null>(null);
    const [orgs, setOrgs] = useState<OrgSummary[]>([]);
    const [error, setError] = useState<UiState | null>(null);
    const [tick, setTick] = useState(0);

    const toLogin = useCallback(() => {
        router.replace(`/login?next=${encodeURIComponent(pathname || '/app')}`);
    }, [router, pathname]);

    useEffect(() => {
        const ctl = new AbortController();
        (async () => {
            setError(null);
            let wanted = storedOrg();
            try {
                let me: SessionInfo;
                try {
                    me = await api.me(wanted, ctl.signal);
                } catch (e) {
                    // A remembered organization that is no longer allowed: forget it, use the home org.
                    if (wanted && e instanceof ApiError && (e.status === 403 || e.status === 400)) {
                        storeOrg(null); wanted = null;
                        me = await api.me(null, ctl.signal);
                    } else throw e;
                }
                // A temporary password blocks every other route (403 password_change_required): load nothing else.
                const list = me.password_change_required ? { items: [] } : await api.orgs(me.active_org.id);
                setSession(me);
                setOrgs(list.items);
            } catch (e) {
                if ((e as Error).name === 'AbortError') return;
                const state = uiState(e);
                if (state === 'unauthorized') { toLogin(); return; }
                setError(state);
            }
        })();
        return () => ctl.abort();
    }, [tick, toLogin]);

    const value = useMemo<SessionValue | null>(() => session && {
        session,
        orgId: session.active_org.id,
        orgs,
        can: (p: string) => session.permissions.includes(p),
        switchOrg: (id: string) => { storeOrg(id === session.home_org.id ? null : id); setTick((t) => t + 1); },
        signOut: async () => {
            try { await api.logout(); } catch { /* already signed out */ }
            storeOrg(null);
            router.replace('/login');
        },
        refresh: () => setTick((t) => t + 1),
    }, [session, orgs, router]);

    if (error) return <>{failed(error, () => setTick((t) => t + 1))}</>;
    if (!value) return <>{loading}</>;
    return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
