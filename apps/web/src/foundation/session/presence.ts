'use client';

// Presence heartbeat: while a NovrSOC tab is open AND visible, tell the API every 60 seconds that the signed-in person is
// working the active organization. Online status (NovrChat "who is online", the team view) comes only from these
// heartbeats. A hidden tab sends nothing; a failed heartbeat is ignored (presence is informational, never blocking).
import { useEffect } from 'react';
import { request } from '@/foundation/api/client';

const PATH = '/api/v1/presence/heartbeat';
const EVERY_MS = 60_000;

export function usePresenceHeartbeat(orgId: string | null): void {
    useEffect(() => {
        if (!orgId) return;
        let stopped = false;
        const beat = () => {
            if (stopped || document.visibilityState !== 'visible') return;
            request<void>(PATH, { method: 'POST', orgId }).catch(() => { /* informational only */ });
        };
        beat();
        const t = setInterval(beat, EVERY_MS);
        const onVisible = () => { if (document.visibilityState === 'visible') beat(); };
        document.addEventListener('visibilitychange', onVisible);
        return () => { stopped = true; clearInterval(t); document.removeEventListener('visibilitychange', onVisible); };
    }, [orgId]);
}
