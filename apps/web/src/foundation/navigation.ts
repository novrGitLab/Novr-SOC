// Role-aware navigation for the V2 shell. Pure module (unit-tested; checked by scripts/check-v2-nav.mjs).
//
// Final product navigation (consolidation). Every item is a routed page backed by the V2 API; sub-pages are internal
// tabs of their module (foundation/ui/module.tsx), never extra sidebar entries. Visibility is a convenience only:
// the API enforces every permission. CNII is shown to holders of cnii:read, but every view still needs an explicit
// designation, enforced by the API.

export type NavIcon = 'overview' | 'posture' | 'reports' | 'alerts' | 'cases' | 'playbooks' | 'soar' | 'handover' | 'sla'
    | 'vms' | 'surface' | 'findings' | 'scans' | 'risk' | 'remediation' | 'vmsreport' | 'insights' | 'actors' | 'cves' | 'nhai'
    | 'cnii' | 'email' | 'brand' | 'assets' | 'chat' | 'recovery' | 'admin' | 'users' | 'billing' | 'analytics' | 'exports'
    | 'wazuh' | 'health' | 'audit' | 'sites' | 'endpoints' | 'collectors' | 'command' | 'policy';

export interface NavItem {
    key: string;
    label: string;
    icon: NavIcon;
    status: 'live' | 'planned';
    href?: string;          // live items only
    permission?: string;    // shown only when the active role holds it
    workstream?: string;    // planned items: who builds it
}

export interface NavSection { title: string; items: NavItem[] }

const live = (key: string, label: string, icon: NavIcon, href: string, permission?: string): NavItem =>
    ({ key, label, icon, status: 'live', href, ...(permission ? { permission } : {}) });

export const FOUNDATION_NAV: NavSection[] = [
    {
        title: 'Workspace',
        items: [
            live('overview', 'Executive overview', 'overview', '/app'),
            live('posture', 'Security posture', 'posture', '/app/posture'),
            live('reports', 'Reports', 'reports', '/app/reports', 'reports:read'),
            live('command', 'Command Center', 'command', '/app/command', 'platform:monitor'),
        ],
    },
    {
        title: 'Security operations',
        items: [
            live('alerts', 'Alerts', 'alerts', '/app/alerts', 'alerts:read'),
            live('cases', 'Cases', 'cases', '/app/cases', 'cases:read'),
            live('playbooks', 'Playbooks', 'playbooks', '/app/playbooks', 'cases:read'),
            live('soar', 'SOAR', 'soar', '/app/soar', 'cases:read'),
            live('handover', 'Shift handover', 'handover', '/app/handover', 'handover:write'),
            live('sla', 'SLA management', 'sla', '/app/sla', 'cases:read'),
        ],
    },
    {
        title: 'Vulnerability management',
        items: [
            live('vms', 'VMS overview', 'vms', '/app/vms', 'vms:read'),
            live('vms-surface', 'Attack surface', 'surface', '/app/vms/surface', 'vms:read'),
            live('vms-findings', 'Findings', 'findings', '/app/vms/findings', 'vms:read'),
            live('vms-scans', 'Scans and schedules', 'scans', '/app/vms/scans', 'vms:read'),
            live('vms-policy', 'Scan policy and enrollment', 'policy', '/app/vms/policy', 'vms:read'),
            live('vms-risk', 'Risk prioritization', 'risk', '/app/vms/risk', 'vms:read'),
            live('vms-remediation', 'Remediation', 'remediation', '/app/vms/remediation', 'vms:read'),
            live('vms-reports', 'Reporting and audit', 'vmsreport', '/app/vms/reports', 'vms:read'),
        ],
    },
    {
        title: 'NHAI threat intelligence',
        items: [
            live('insights', 'Threat Insights', 'insights', '/app/insights', 'intel:read'),
            live('actors', 'Threat actors', 'actors', '/app/insights/actors', 'intel:read'),
            live('cves', 'CVE intelligence', 'cves', '/app/insights/cves', 'intel:read'),
            live('nhai', 'NHAI analyses', 'nhai', '/app/nhai', 'nhai:analyze'),
        ],
    },
    {
        title: 'Protection',
        items: [
            live('cnii', 'CNII monitoring', 'cnii', '/app/cnii', 'cnii:read'),
            live('email', 'Email security', 'email', '/app/email', 'protection:read'),
            live('brand', 'Brand protection', 'brand', '/app/brand', 'protection:read'),
        ],
    },
    {
        title: 'Assets',
        items: [live('assets', 'Asset inventory', 'assets', '/app/assets', 'assets:read')],
    },
    {
        title: 'Assistant and continuity',
        items: [
            live('chat', 'NovrChat', 'chat', '/app/chat', 'chat:use'),
            live('recovery', 'Data loss recovery', 'recovery', '/app/recovery', 'recovery:read'),
        ],
    },
    {
        title: 'Clients and administration',
        items: [
            live('admin', 'Organizations', 'admin', '/app/admin', 'users:manage'),
            live('admin-users', 'Users and teams', 'users', '/app/admin/users', 'users:manage'),
            live('admin-billing', 'Billing', 'billing', '/app/admin/billing', 'billing:manage'),
            live('admin-analytics', 'Platform analytics', 'analytics', '/app/admin/analytics', 'platform:monitor'),
            live('admin-exports', 'Data exports', 'exports', '/app/admin/exports', 'exports:manage'),
            live('admin-agent-groups', 'NovrAgent group mappings', 'wazuh', '/app/admin/agent-groups', 'endpoints:read'),
            live('admin-health', 'Platform health', 'health', '/app/admin/health', 'platform:monitor'),
            live('audit', 'Audit log', 'audit', '/app/audit', 'audit:read'),
        ],
    },
];

/** Sections and items the given permission set may see; empty sections are dropped. */
export function visibleNav(permissions: readonly string[], sections: NavSection[] = FOUNDATION_NAV): NavSection[] {
    const held = new Set(permissions);
    return sections
        .map((s) => ({ ...s, items: s.items.filter((i) => !i.permission || held.has(i.permission)) }))
        .filter((s) => s.items.length > 0);
}

/** Every href a live item routes to (the nav check verifies each has a page). */
export function liveHrefs(sections: NavSection[] = FOUNDATION_NAV): string[] {
    return sections.flatMap((s) => s.items.filter((i) => i.status === 'live' && i.href).map((i) => i.href as string));
}

/** Whether the pathname belongs to an item (exact, or a child route of a non-root item). */
export function isActive(item: NavItem, pathname: string): boolean {
    if (!item.href) return false;
    return item.href === '/app' ? pathname === '/app' : pathname === item.href || pathname.startsWith(`${item.href}/`);
}
