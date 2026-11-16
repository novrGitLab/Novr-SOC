'use client';

// Telemetry attribution of the ACTIVE organization: Wazuh agent groups (agents' alerts) and syslog / agentless sources
// (events the Wazuh manager receives itself, agent 000). An event's organization is decided only by these; everything
// else is quarantined. Platform administrators manage every organization from Organizations -> Integrations.
import { Activity } from 'lucide-react';
import { PageHeader } from '@/components/features/vms/kit';
import { useSession } from '@/foundation/session/SessionProvider';
import { GroupMappingsPanel } from '../_org/GroupMappingsPanel';
import { LogSourcesPanel } from '../_org/LogSourcesPanel';
import { QuarantinePanel } from '../_org/QuarantinePanel';

export default function WazuhGroupsPage() {
    const { orgId, can, session } = useSession();
    return (
        <>
            <PageHeader title="Wazuh group mappings" icon={Activity}
                description={`How security events are attributed to ${session.active_org.name}: Wazuh agent groups for agents, registered sources for syslog and agentless devices. A group or source belongs to at most one organization.`} />
            <GroupMappingsPanel orgId={orgId} orgName={session.active_org.name} canManage={can('endpoints:manage')} />
            <LogSourcesPanel orgId={orgId} orgName={session.active_org.name} canManage={can('endpoints:manage')} />
            <QuarantinePanel />
        </>
    );
}
