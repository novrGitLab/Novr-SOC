// The Asset inventory module's internal tabs (shared by its own pages and the Wazuh endpoints and Sites pages).
import type { ModuleTab } from '@/foundation/ui/module';

export const ASSET_TABS: ModuleTab[] = [
    { href: '/app/assets', label: 'Inventory' },
    { href: '/app/assets/collectors', label: 'Collectors and discovery' },
    { href: '/app/endpoints', label: 'NovrAgent endpoints', permission: 'endpoints:read' },
    { href: '/app/sites', label: 'Sites', permission: 'sites:read' },
];
