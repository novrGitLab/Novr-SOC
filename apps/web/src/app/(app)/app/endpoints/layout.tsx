'use client';

import type { ReactNode } from 'react';
import { ModuleTabs } from '@/foundation/ui/module';
import { ASSET_TABS } from '../assets/tabs';

export default function AssetsLayout({ children }: { children: ReactNode }) {
    return <><ModuleTabs tabs={ASSET_TABS.map((t) => (t.href === '/app/assets' ? { ...t, exact: false } : t))} label="Asset inventory sections" />{children}</>;
}
