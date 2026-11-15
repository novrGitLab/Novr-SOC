'use client';

import type { ReactNode } from 'react';
import { ModuleTabs } from '@/foundation/ui/module';

const TABS = [
    { href: '/app/soar', label: 'Operations centre', exact: true }, { href: '/app/soar/runs', label: 'Runs' },
    { href: '/app/soar/approvals', label: 'Approvals' }, { href: '/app/soar/ai', label: 'AI activity' }, { href: '/app/soar/policy', label: 'Response policy' },
];

export default function SoarLayout({ children }: { children: ReactNode }) {
    return <><ModuleTabs tabs={TABS} label="SOAR sections" />{children}</>;
}
