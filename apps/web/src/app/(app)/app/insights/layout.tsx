'use client';

import type { ReactNode } from 'react';
import { ModuleTabs } from '@/foundation/ui/module';

const TABS = [
    { href: '/app/insights', label: 'Threat Insights', exact: true }, { href: '/app/insights/actors', label: 'Threat actors' },
    { href: '/app/insights/cves', label: 'CVE intelligence' }, { href: '/app/nhai', label: 'NHAI analyses', permission: 'nhai:analyze' },
];

export default function InsightsLayout({ children }: { children: ReactNode }) {
    return <><ModuleTabs tabs={TABS} label="Threat intelligence sections" />{children}</>;
}
