'use client';

// Organization onboarding: what the ACTIVE organization still needs, each step read from its real configuration.
import Link from 'next/link';
import { useCallback } from 'react';
import { CheckCircle2, Circle } from 'lucide-react';
import { adminxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { Loaded } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';

const STEPS: Record<string, { label: string; href: string }> = {
    organization_created: { label: 'Organization created', href: '/app/admin' },
    users_added: { label: 'Users and analysts added', href: '/app/admin/users' },
    wazuh_groups_mapped: { label: 'Wazuh agent groups mapped', href: '/app/admin/wazuh-groups' },
    sites_defined: { label: 'Sites and networks defined', href: '/app/sites' },
    sla_policies_set: { label: 'SLA policies set', href: '/app/sla' },
    response_policy_set: { label: 'SOAR response policy set', href: '/app/soar/policy' },
    subscription_set: { label: 'Plan and subscription recorded', href: '/app/admin/billing' },
    assets_inventoried: { label: 'Assets in the inventory', href: '/app/assets' },
};

export function OnboardingPanel() {
    const { orgId, session } = useSession();
    const ob = useResource(useCallback(() => adminxApi.onboarding(orgId), [orgId]));
    return (
        <Loaded title={`Onboarding: ${session.active_org.name}`} hint="Each step is read from the organization's configuration" data={ob.data} error={ob.error} reload={ob.reload} testid="onboarding">
            {(d) => (
                <ol className="grid sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
                    {Object.entries(d.steps).map(([k, done]) => (
                        <li key={k} className="flex items-center gap-2 rounded-lg border border-border p-2" data-done={done}>
                            {done ? <CheckCircle2 className="w-4 h-4 text-[var(--vz-good)] shrink-0" aria-hidden /> : <Circle className="w-4 h-4 text-foreground-muted shrink-0" aria-hidden />}
                            <Link href={STEPS[k]?.href ?? '/app/admin'} className={done ? '' : 'font-semibold underline'}>{STEPS[k]?.label ?? k}</Link>
                            <span className="sr-only">{done ? 'done' : 'to do'}</span>
                        </li>
                    ))}
                </ol>
            )}
        </Loaded>
    );
}
