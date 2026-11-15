'use client';

import type { ReactNode } from 'react';
import { ModuleTabs } from '@/foundation/ui/module';

const TABS = [
    { href: '/app/cnii', label: 'Monitored assets', exact: true }, { href: '/app/cnii/authorizations', label: 'Authorizations' },
    { href: '/app/cnii/designations', label: 'Designations and sectors' },
];

export default function CniiLayout({ children }: { children: ReactNode }) {
    return <><ModuleTabs tabs={TABS} label="CNII sections" />{children}</>;
}
