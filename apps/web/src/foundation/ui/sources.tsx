'use client';

// Honest data-source indicators shared by the Phase 4 pages. A connector is only ever shown as
// "Connected" when the API reports `connected`; local fixture data is always labelled as such.
import { FlaskConical } from 'lucide-react';
import { StatusPill, type Tone } from '@/components/features/vms/ui';
import type { ConnectorState } from '@/foundation/api/platform';

type SourceState = ConnectorState['state'];

export const SOURCE_STATE: Record<SourceState, { label: string; tone: Tone }> = {
    unconfigured: { label: 'Not configured', tone: 'neutral' },
    local_fixture: { label: 'Local fixture data', tone: 'warning' },
    connected: { label: 'Connected', tone: 'good' },
    unavailable: { label: 'Unavailable', tone: 'serious' },
    error: { label: 'Error', tone: 'critical' },
};

export const CONNECTOR_LABEL: Record<ConnectorState['connector'], string> = {
    wazuh_manager: 'NovrSIEM', wazuh_indexer: 'NovrSIEM event store', ollama: 'NHAI interface',
};

export function SourcePill({ state }: { state: SourceState }) {
    const m = SOURCE_STATE[state];
    return <StatusPill tone={m.tone} label={m.label} />;
}

/** A banner stating where the data on a page comes from. Shown on every page fed by a connector. */
export function SourceBanner({ source, what }: { source: ConnectorState; what: string }) {
    if (source.state === 'connected') return null;
    const fixture = source.state === 'local_fixture';
    return (
        <div role="note" data-testid="source-banner" data-state={source.state}
            className="flex items-start gap-3 rounded-xl border border-border bg-card p-3.5">
            {fixture ? <FlaskConical className="w-5 h-5 mt-0.5 shrink-0 text-foreground-muted" aria-hidden /> : null}
            <div className="min-w-0 text-xs">
                <p className="font-bold text-foreground flex flex-wrap items-center gap-2">
                    {fixture ? `${what}: local fixture data` : `${what}: ${SOURCE_STATE[source.state].label.toLowerCase()}`}
                    <SourcePill state={source.state} />
                </p>
                <p className="text-foreground-muted mt-0.5">{source.detail || (fixture ? 'Local test data. Not live telemetry.' : '')}</p>
            </div>
        </div>
    );
}

export const fmtDateTime = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString('en-GB') : '—');

export const ALERT_STATUS_LABEL: Record<string, string> = {
    new: 'New', acknowledged: 'Acknowledged', in_progress: 'In progress', closed: 'Closed',
};
export const CASE_STATUS_LABEL: Record<string, string> = {
    open: 'Open', in_progress: 'In progress', resolved: 'Resolved', closed: 'Closed',
};
export const STATUS_TONE: Record<string, Tone> = {
    new: 'warning', acknowledged: 'neutral', in_progress: 'neutral', closed: 'good', open: 'warning', resolved: 'good',
};

/** A tag shown next to any record that came from the local fixture. */
export function FixtureTag() {
    return (
        <span title="Local fixture data for development and tests. Not live telemetry." data-testid="fixture-tag"
            className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded bg-card-muted text-foreground-muted">
            <FlaskConical className="w-3 h-3" aria-hidden />Fixture
        </span>
    );
}

export const inputCls = 'bg-card border border-border rounded-lg px-2.5 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-purple/40';

export const AGENT_STATUS: Record<string, { label: string; tone: Tone }> = {
    active: { label: 'Active', tone: 'good' },
    disconnected: { label: 'Disconnected', tone: 'serious' },
    never_connected: { label: 'Never connected', tone: 'neutral' },
    pending: { label: 'Pending', tone: 'warning' },
};
export const OS_SUPPORT: Record<string, string> = { supported: 'Supported', unsupported: 'Unsupported', unknown: 'Support unknown' };

export const REPORT_LABEL: Record<string, string> = { organization_summary: 'Organization summary' };

export const SECTION_STATE: Record<string, { label: string; tone: Tone }> = {
    ok: { label: 'Data available', tone: 'good' },
    empty: { label: 'No records in period', tone: 'neutral' },
    local_fixture: { label: 'Local fixture data', tone: 'warning' },
    integration_unconfigured: { label: 'Source not configured', tone: 'neutral' },
    not_permitted: { label: 'Not permitted for your role', tone: 'neutral' },
    error: { label: 'Source error', tone: 'critical' },
};
