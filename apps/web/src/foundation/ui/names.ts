// Product names for values that come from the API as identifiers (contract values that are never renamed). Every place
// that shows such a value goes through these maps, so infrastructure and vendor names never reach the screen.
// Product vocabulary: NovrSIEM (detection engine), NovrAgent (endpoint agents), NovrVMS (scanning),
// NovrFORWARDER (telemetry forwarding), NovrSOAR (response execution), NHAI (analysis; its model runtime: "NHAI interface").

const SOURCES: Record<string, string> = {
    wazuh: 'NovrAgent', wazuh_manager: 'NovrSIEM', wazuh_indexer: 'NovrSIEM event store', wazuh_sync: 'NovrAgent sync',
    vms: 'NovrVMS', manual: 'manual entry', log_source: 'log source', collector: 'collector', email: 'email domain',
    local_fixture: 'local fixture', stix: 'STIX', taxii: 'TAXII', brand_protection: 'brand protection', email_security: 'email security',
};

const ACTIVITIES: Record<string, string> = {
    vuln_openvas: 'NovrVMS vulnerability scan', vuln_nuclei: 'NovrVMS web exposure checks', ports: 'NovrVMS service discovery',
    discovery: 'NovrVMS discovery',
};

const IDENTITY_KINDS: Record<string, string> = {
    vms_worker: 'NovrVMS', forwarder: 'NovrFORWARDER', ti_feeder: 'Threat intelligence feeder', email_gateway: 'Email gateway',
    collector: 'Collector', backup_agent: 'Backup agent',
};

const IDENTIFIER_KINDS: Record<string, string> = { wazuh_agent: 'NovrAgent id' };

const pretty = (v: string) => v.replace(/_/g, ' ');

/** A data source or connector (asset sources, sync runs, alert sources, connectors). */
export const sourceName = (v: string | null | undefined) => (v ? SOURCES[v] ?? pretty(v) : '—');
/** A VMS scan activity (vuln_openvas, ports, ...). */
export const activityName = (v: string | null | undefined) => (v ? ACTIVITIES[v] ?? pretty(v) : '—');
/** A machine identity kind (vms_worker, forwarder, ...). */
export const identityKindName = (v: string | null | undefined) => (v ? IDENTITY_KINDS[v] ?? pretty(v) : '—');
/** An asset identifier kind (wazuh_agent, ip, fqdn, ...). */
export const identifierKindName = (v: string) => IDENTIFIER_KINDS[v] ?? v;
