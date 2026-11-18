// Labels and tones shared by the organization directory, the organization page and the telemetry panels.
import type { Schemas } from '@/foundation/api/client';
import type { Tone } from '@/components/features/vms/ui';

export type OrgTab = 'overview' | 'users' | 'assets' | 'integrations' | 'policies' | 'billing' | 'audit' | 'settings';

export const ORG_TABS: readonly (readonly [OrgTab, string])[] = [
    ['overview', 'Overview'], ['users', 'Users and teams'], ['assets', 'Assets, sites and networks'], ['integrations', 'Integrations'],
    ['policies', 'Security policies'], ['billing', 'Billing and subscription'], ['audit', 'Audit activity'], ['settings', 'Settings'],
];

/** Each onboarding step and where it is configured (a tab of the organization page). */
export const ONBOARDING_STEPS: Record<string, { label: string; tab: OrgTab; hint: string }> = {
    organization_created: { label: 'Organization created', tab: 'settings', hint: 'The organization record exists.' },
    profile_completed: { label: 'Contact and profile', tab: 'settings', hint: 'A contact name and e-mail are recorded.' },
    users_added: { label: 'Users and analysts', tab: 'users', hint: 'At least one member (home or assigned).' },
    telemetry_configured: { label: 'Telemetry attributed', tab: 'integrations', hint: 'NovrAgent groups mapped or syslog / agentless sources registered.' },
    wazuh_groups_mapped: { label: 'NovrAgent groups mapped', tab: 'integrations', hint: 'Optional when the organization uses syslog only.' },
    log_sources_registered: { label: 'Syslog / agentless sources', tab: 'integrations', hint: 'Optional when the organization uses NovrAgents only.' },
    telemetry_received: { label: 'First security event received', tab: 'integrations', hint: 'An alert has been stored for the organization.' },
    sites_defined: { label: 'Sites and networks', tab: 'assets', hint: 'At least one site with its networks.' },
    assets_inventoried: { label: 'Assets in the inventory', tab: 'assets', hint: 'Reconciled from NovrAgents, sources or entered.' },
    sla_policies_set: { label: 'SLA policies', tab: 'policies', hint: 'Response and resolution targets per severity.' },
    response_policy_set: { label: 'SOAR response policy', tab: 'policies', hint: 'Which actions may be approved, on which groups.' },
    subscription_set: { label: 'Plan and subscription', tab: 'billing', hint: 'A plan recorded (no payment is taken).' },
};

export const HEALTH: Record<Schemas['OrgIntegrations']['health'], { label: string; tone: Tone }> = {
    ok: { label: 'Healthy', tone: 'good' }, attention: { label: 'Needs attention', tone: 'warning' },
    not_configured: { label: 'Not configured', tone: 'neutral' }, inactive: { label: 'Inactive', tone: 'neutral' },
};

export const ORG_STATUS: Record<Schemas['OrgDirectoryRow']['status'], { label: string; tone: Tone }> = {
    active: { label: 'Active', tone: 'good' }, suspended: { label: 'Suspended', tone: 'warning' }, archived: { label: 'Archived', tone: 'neutral' },
};

export const SOURCE_STATUS: Record<Schemas['LogSourceView']['status'], { label: string; tone: Tone }> = {
    receiving: { label: 'Receiving', tone: 'good' }, quiet: { label: 'Quiet (last 24 h)', tone: 'warning' },
    silent: { label: 'Silent', tone: 'serious' }, never_received: { label: 'No event yet', tone: 'neutral' },
    disabled: { label: 'Disabled', tone: 'neutral' }, retired: { label: 'Retired', tone: 'neutral' },
};

export const DEVICE_TYPES: readonly (readonly [Schemas['LogSourceCreate']['device_type'], string])[] = [
    ['firewall', 'Firewall'], ['router', 'Router'], ['switch', 'Switch'], ['linux_server', 'Linux server'], ['windows_server', 'Windows server'],
    ['network_appliance', 'Network appliance'], ['storage', 'Storage'], ['other', 'Other syslog device'],
];
export const deviceLabel = (t: string) => DEVICE_TYPES.find(([k]) => k === t)?.[1] ?? t;

export const orgHref = (id: string, tab?: OrgTab) => `/app/admin/organizations/${id}${tab && tab !== 'overview' ? `?tab=${tab}` : ''}`;
