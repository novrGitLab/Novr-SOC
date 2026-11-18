'use client';

// Human approvals (a SOAR sub-page): pending decisions first, then the decision history. The requester never decides.
import { useCallback } from 'react';
import { ShieldCheck } from 'lucide-react';
import { PageHeader } from '@/components/features/vms/kit';
import { Card } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { Loaded } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';
import { ApprovalRow } from '../ApprovalRow';
import { soarApi } from '../api';

export default function SoarApprovalsPage() {
    const { orgId, can } = useSession();
    const all = useResource(useCallback(() => soarApi.approvals(orgId, false), [orgId]));
    return (
        <>
            <PageHeader title="Approvals" icon={ShieldCheck}
                description="Every consequential response step waits here for a second person. Approval re-checks the target and the policy, then dispatches to NovrSOAR, which returns a signed receipt." />
            <Loaded title="Pending and decided approvals" data={all.data} error={all.error} reload={all.reload} testid="approvals">
                {(d) => d.items.length === 0 ? <p className="text-xs text-foreground-muted">No approval has been requested yet.</p>
                    : <ul className="divide-y divide-border">{d.items.map((a) => <ApprovalRow key={a.id} a={a} onDone={all.reload} />)}</ul>}
            </Loaded>
            {!can('response:approve') && <Card><p className="text-xs text-foreground-muted">Approving response actions requires the response:approve permission (SOC managers).</p></Card>}
        </>
    );
}
