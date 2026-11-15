'use client';

// Audit log of the active organization: append-only, filtered server-side by action (or prefix), outcome, actor,
// resource and time, with details. Covers authentication, permissions, configuration, exports, AI activity, approvals,
// response execution and administration.
import { useCallback, useState } from 'react';
import { ChevronLeft, ChevronRight, ScrollText } from 'lucide-react';
import { PageHeader, Select, Tag, btn } from '@/components/features/vms/kit';
import { adminxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';

const PAGE = 100;
const OUTCOMES = [['', 'Any outcome'], ['success', 'Success'], ['denied', 'Denied'], ['failure', 'Failure']] as const;
const AREAS = [['', 'Every action'], ['LOGIN_', 'Sign-in'], ['PERMISSION_', 'Permission denials'], ['SOAR_', 'SOAR'], ['NHAI_', 'NHAI'], ['CASE_', 'Cases'],
    ['ALERT_', 'Alerts'], ['VMS_', 'VMS'], ['ASSET_', 'Assets'], ['TI_', 'Threat intelligence'], ['CNII_', 'CNII'], ['DATA_EXPORT_', 'Exports'],
    ['RECOVERY_', 'Recovery'], ['USER_', 'Users'], ['CHAT_', 'NovrChat'], ['SLA_', 'SLA'], ['HANDOVER_', 'Handover']] as const;

export default function AuditPage() {
    const { orgId, session } = useSession();
    const [area, setArea] = useState<(typeof AREAS)[number][0]>('');
    const [outcome, setOutcome] = useState<(typeof OUTCOMES)[number][0]>('');
    const [actor, setActor] = useState('');
    const [since, setSince] = useState('');
    const [offset, setOffset] = useState(0);
    const events = useResource(useCallback(() => adminxApi.audit(orgId, { limit: PAGE, offset, action: area || undefined, outcome: outcome || undefined,
        actor: actor || undefined, since: since ? new Date(since).toISOString() : undefined }), [orgId, offset, area, outcome, actor, since]));
    const reset = () => setOffset(0);
    return (
        <>
            <PageHeader title="Audit log" icon={ScrollText} description={`Append-only record of actions in ${session.active_org.name}: sign-ins, denials, triage, cases, SOAR approvals and receipts, AI activity, exports, administration and CNII access.`} />
            <div className="flex flex-wrap items-end gap-2">
                <Select label="Area" options={AREAS} value={area} onChange={(v) => { setArea(v); reset(); }} />
                <Select label="Outcome" options={OUTCOMES} value={outcome} onChange={(v) => { setOutcome(v); reset(); }} />
                <Field label="Actor contains"><TextInput value={actor} onChange={(e) => { setActor(e.target.value); reset(); }} aria-label="Filter by actor" /></Field>
                <Field label="Since"><TextInput type="datetime-local" value={since} onChange={(e) => { setSince(e.target.value); reset(); }} /></Field>
            </div>
            <Loaded title="Events" hint={events.data?.total !== undefined && events.data?.total !== null ? `${events.data.total} event(s)` : undefined} data={events.data} error={events.error} reload={events.reload}>
                {(d) => (
                    <>
                        <DataTable testid="audit-table" rows={d.items} rowKey={(e) => String(e.id)} empty="No events match." columns={[
                            { key: 't', header: 'When', render: (e) => <span className="text-xs whitespace-nowrap">{fmt(e.occurred_at)}</span> },
                            { key: 'a', header: 'Action', render: (e) => <span className="font-mono text-xs">{e.action}</span> },
                            { key: 'o', header: 'Outcome', render: (e) => <Tag strong={e.outcome !== 'success'}>{e.outcome}</Tag> },
                            { key: 'u', header: 'Actor', render: (e) => <span className="text-xs">{e.actor_label} ({e.actor_type})</span> },
                            { key: 'r', header: 'Resource', className: 'hidden md:table-cell', render: (e) => <span className="text-[11px] font-mono">{e.resource_type} {e.resource_id}</span> },
                            { key: 'd', header: 'Details', className: 'hidden lg:table-cell', render: (e) => <span className="text-[11px]">{Object.keys(e.details ?? {}).length ? JSON.stringify(e.details).slice(0, 160) : ''}</span> },
                        ]} />
                        <div className="flex justify-end gap-1.5 mt-2">
                            <button className={btn('secondary')} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}><ChevronLeft className="w-3.5 h-3.5" aria-hidden /> Newer</button>
                            <button className={btn('secondary')} disabled={d.items.length < PAGE} onClick={() => setOffset(offset + PAGE)}>Older <ChevronRight className="w-3.5 h-3.5" aria-hidden /></button>
                        </div>
                    </>
                )}
            </Loaded>
        </>
    );
}
