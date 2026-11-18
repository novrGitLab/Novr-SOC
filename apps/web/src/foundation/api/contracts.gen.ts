// GENERATED from packages/contracts/openapi/novrsoc-contracts.v1.json by scripts/check-api-types.mjs. Do not edit.
// Regenerate: npm run api:types (after scripts/contracts/export.py).

export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /**
         * ActionType
         * @enum {string}
         */
        ActionType: "enrich_iocs" | "notify_email" | "notify_ciso" | "create_task" | "block_ip" | "isolate_agent" | "disable_account";
        /** ActorLinkCreate */
        ActorLinkCreate: {
            /**
             * Association
             * @enum {string}
             */
            association: "verified" | "suspected";
            /**
             * Link Type
             * @enum {string}
             */
            link_type: "indicator" | "cve" | "case" | "alert" | "asset";
            /** Rationale */
            rationale: string;
            /** Ref Id */
            ref_id: string;
        };
        /** ActorLinkView */
        ActorLinkView: {
            /**
             * Association
             * @enum {string}
             */
            association: "verified" | "suspected";
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Created Label */
            created_label: string;
            /**
             * Exists
             * @description False when the linked record is no longer visible in this organization
             */
            exists: boolean;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Link Type
             * @enum {string}
             */
            link_type: "indicator" | "cve" | "case" | "alert" | "asset";
            /** Rationale */
            rationale: string;
            /** Ref Id */
            ref_id: string;
        };
        /** ActorRef */
        ActorRef: {
            /**
             * Id
             * @default null
             */
            id: string | null;
            /**
             * Label
             * @default
             */
            label: string;
            /**
             * Type
             * @enum {string}
             */
            type: "user" | "service" | "system";
        };
        /** ActorSource */
        ActorSource: {
            /** Name */
            name: string;
            /**
             * Published
             * @default null
             */
            published: string | null;
            /**
             * Url
             * @default
             */
            url: string;
        };
        /** AdminOrg */
        AdminOrg: {
            /**
             * Archived At
             * @default null
             */
            archived_at: string | null;
            /**
             * Contact Email
             * @default
             */
            contact_email: string;
            /**
             * Contact Name
             * @default
             */
            contact_name: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "platform" | "client";
            /** Name */
            name: string;
            /**
             * Notes
             * @default
             */
            notes: string;
            /** Slug */
            slug: string;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "suspended" | "archived";
            /**
             * Status Reason
             * @default
             */
            status_reason: string;
            /**
             * Timezone
             * @default UTC
             */
            timezone: string;
            /**
             * Updated At
             * @default null
             */
            updated_at: string | null;
        };
        /** AdminOrgCreate */
        AdminOrgCreate: {
            /**
             * Contact Email
             * @default
             */
            contact_email: string;
            /**
             * Contact Name
             * @default
             */
            contact_name: string;
            /** Name */
            name: string;
            /** Slug */
            slug: string;
            /**
             * Timezone
             * @default UTC
             */
            timezone: string;
        };
        /** AdminOrgList */
        AdminOrgList: {
            /** Items */
            items: components["schemas"]["AdminOrg"][];
        };
        /** AdminUser */
        AdminUser: {
            /**
             * Access Scope
             * @enum {string}
             */
            access_scope: "home" | "operations" | "reporting";
            /** Display Name */
            display_name: string;
            /** Email */
            email: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Last Login At
             * @default null
             */
            last_login_at: string | null;
            /** Locked */
            locked: boolean;
            /**
             * Role
             * @enum {string}
             */
            role: "super_admin" | "soc_manager" | "analyst" | "executive" | "portal_user";
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "disabled";
        };
        /** AdminUserCreate */
        AdminUserCreate: {
            /**
             * Access Scope
             * @default home
             * @enum {string}
             */
            access_scope: "home" | "operations" | "reporting";
            /**
             * Display Name
             * @default
             */
            display_name: string;
            /** Email */
            email: string;
            /**
             * Role
             * @enum {string}
             */
            role: "super_admin" | "soc_manager" | "analyst" | "executive" | "portal_user";
        };
        /**
         * AdminUserCreated
         * @description The temporary password is shown ONCE, here; it is stored only as a hash.
         */
        AdminUserCreated: {
            /** Temporary Password */
            temporary_password: string;
            user: components["schemas"]["AdminUser"];
        };
        /** AdminUserList */
        AdminUserList: {
            /** Items */
            items: components["schemas"]["AdminUser"][];
        };
        /** AiActivityList */
        AiActivityList: {
            /** Items */
            items: components["schemas"]["AiActivityView"][];
            /**
             * Note
             * @default AI analysis only. Nothing listed here executed a response action; execution is recorded by the SOAR engine.
             */
            note: string;
        };
        /** AiActivityView */
        AiActivityView: {
            actor: components["schemas"]["ActorRef"];
            /**
             * Details
             * @default {}
             */
            details: {
                [key: string]: unknown;
            };
            /** Id */
            id: number;
            /**
             * Kind
             * @enum {string}
             */
            kind: "analysis_requested" | "analysis_completed" | "analysis_failed" | "recommendation" | "proposed_action" | "review" | "chat_question" | "chat_answer" | "chat_refused";
            /** Model */
            model: string;
            /** Module */
            module: string;
            /**
             * Nhai Job Id
             * @default null
             */
            nhai_job_id: string | null;
            /**
             * Occurred At
             * Format: date-time
             */
            occurred_at: string;
            /**
             * Outcome
             * @enum {string}
             */
            outcome: "success" | "failure" | "pending" | "refused";
            /** Subject Id */
            subject_id: string;
            /** Subject Type */
            subject_type: string;
            /** Summary */
            summary: string;
            /** Task */
            task: string;
        };
        /** AlertClassification */
        AlertClassification: {
            /** Id */
            id: string;
            /**
             * Log Source Id
             * @default null
             */
            log_source_id: string | null;
            /**
             * Org Id
             * @default null
             */
            org_id: string | null;
            /**
             * Org Slug
             * @default null
             */
            org_slug: string | null;
            /**
             * Reason
             * @description The quarantine reason (the same values ingest records)
             * @default null
             */
            reason: string | null;
            /**
             * Verdict
             * @description new: ingest would store it; duplicate: already stored for its organization; quarantine: no organization
             * @enum {string}
             */
            verdict: "new" | "duplicate" | "quarantine";
        };
        /**
         * AlertClassifyRequest
         * @description Dry run of ingest (historical backfill planning): the same ownership decision as ingest, nothing is stored.
         */
        AlertClassifyRequest: {
            /** Alerts */
            alerts: components["schemas"]["WazuhAlertIn"][];
        };
        /** AlertClassifyResult */
        AlertClassifyResult: {
            /**
             * Classified At
             * Format: date-time
             */
            classified_at: string;
            /** Items */
            items: components["schemas"]["AlertClassification"][];
        };
        /** AlertDetail */
        AlertDetail: {
            /** Agent Groups */
            agent_groups: string[];
            /** Agent Id */
            agent_id: string;
            /** Agent Name */
            agent_name: string;
            /**
             * Asset Id
             * @description Consolidation: the canonical asset of the alert's agent
             * @default null
             */
            asset_id: string | null;
            /**
             * Assignee Id
             * @default null
             */
            assignee_id: string | null;
            /**
             * Assignee Label
             * @default null
             */
            assignee_label: string | null;
            /**
             * Case Id
             * @description The case this alert is linked to, if any (the most recently linked one when several)
             * @default null
             */
            case_id: string | null;
            /** External Id */
            external_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Log Source Id
             * @description The registered syslog or agentless source the alert came from (events of the Wazuh manager, agent 000), if any
             * @default null
             */
            log_source_id: string | null;
            /**
             * Log Source Name
             * @default null
             */
            log_source_name: string | null;
            /** Mitre Techniques */
            mitre_techniques: string[];
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            /** Raw */
            raw: {
                [key: string]: unknown;
            };
            /**
             * Received At
             * Format: date-time
             */
            received_at: string;
            /** Rule Description */
            rule_description: string;
            /** Rule Id */
            rule_id: string;
            /** Rule Level */
            rule_level: number;
            severity: components["schemas"]["Severity"];
            /**
             * Source
             * @enum {string}
             */
            source: "wazuh" | "local_fixture";
            /** Src Ip */
            src_ip: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "new" | "acknowledged" | "in_progress" | "closed";
            /** Status Reason */
            status_reason: string;
        };
        /**
         * AlertEvidence
         * @description The original alert document for one stored alert, as read from its source by the API (never by the browser).
         *     `source.state` says where it came from: `connected` (read live from the Wazuh indexer just now), `local_fixture`
         *     (the stored fixture copy, labelled), or an unavailable state with `document` null. Secrets are redacted.
         */
        AlertEvidence: {
            /**
             * Alert Id
             * Format: uuid
             */
            alert_id: string;
            /**
             * Document
             * @default null
             */
            document: {
                [key: string]: unknown;
            } | null;
            /** External Id */
            external_id: string;
            /**
             * Redacted
             * @default true
             */
            redacted: boolean;
            /**
             * Retrieved At
             * Format: date-time
             */
            retrieved_at: string;
            source: components["schemas"]["ConnectorState"];
        };
        /** AlertExplanationRequest */
        AlertExplanationRequest: {
            /**
             * Alert Id
             * Format: uuid
             */
            alert_id: string;
        };
        /** AlertIngestBatch */
        AlertIngestBatch: {
            /** Alerts */
            alerts: components["schemas"]["WazuhAlertIn"][];
            /**
             * Batch Id
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            batch_id: string;
        };
        /** AlertIngestResult */
        AlertIngestResult: {
            /** Accepted */
            accepted: number;
            /** Batch Id */
            batch_id: string;
            /** Duplicates */
            duplicates: number;
            /**
             * Durable
             * @default true
             * @constant
             */
            durable: true;
            /** Quarantined */
            quarantined: number;
            /**
             * Replayed
             * @description Phase 5: True when this batch_id was already acknowledged; the stored acknowledgement is returned and nothing is ingested again
             * @default false
             */
            replayed: boolean;
        };
        /** AlertList */
        AlertList: {
            /** Items */
            items: components["schemas"]["StoredAlert"][];
            /** Limit */
            limit: number;
            /** Offset */
            offset: number;
            /** Total */
            total: number;
        };
        /** AlertStatusUpdate */
        AlertStatusUpdate: {
            /**
             * Reason
             * @default
             */
            reason: string;
            /**
             * Status
             * @enum {string}
             */
            status: "new" | "acknowledged" | "in_progress" | "closed";
        };
        /**
         * AlertToCasePromotion
         * @description Analyst (cases:write) promotes stored alerts to a case. Dedupe key: (org, source, source_id).
         */
        AlertToCasePromotion: {
            /** Alert Ids */
            alert_ids: string[];
            /**
             * Assignee Id
             * @default null
             */
            assignee_id: string | null;
            severity: components["schemas"]["Severity"];
            /**
             * Source
             * @default alert
             */
            source: string;
            /**
             * Source Id
             * @description With org and source, the case dedupe key; a repeat returns the existing case
             */
            source_id: string;
            /**
             * Summary
             * @default
             */
            summary: string;
            /** Title */
            title: string;
        };
        /** ApprovalDecision */
        ApprovalDecision: {
            /**
             * Approval Id
             * Format: uuid
             */
            approval_id: string;
            decided_by: components["schemas"]["ActorRef"];
            /**
             * Decision
             * @enum {string}
             */
            decision: "approve" | "reject";
            /** Reason */
            reason: string;
            /** @description Echoed from the request so self-approval is checked in the contract too */
            requested_by: components["schemas"]["ActorRef"];
        };
        /**
         * ApprovalDecisionRequest
         * @description The human decision. The decider is the signed-in user (never the requester).
         */
        ApprovalDecisionRequest: {
            /**
             * Decision
             * @enum {string}
             */
            decision: "approve" | "reject";
            /** Reason */
            reason: string;
        };
        /** ApprovalList */
        ApprovalList: {
            /** Items */
            items: components["schemas"]["ApprovalView"][];
        };
        /** ApprovalRequest */
        ApprovalRequest: {
            action: components["schemas"]["ActionType"];
            /**
             * Idempotency Key
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            idempotency_key: string;
            /** Justification */
            justification: string;
            requested_by: components["schemas"]["ActorRef"];
            /**
             * Run Id
             * Format: uuid
             */
            run_id: string;
            /** Step Key */
            step_key: string;
            /** Target */
            target: string;
        };
        /** ApprovalView */
        ApprovalView: {
            action: components["schemas"]["ActionType"];
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** @default null */
            decided_by: components["schemas"]["ActorRef"] | null;
            /**
             * Decision
             * @default null
             */
            decision: ("approve" | "reject") | null;
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Justification */
            justification: string;
            /**
             * Reason
             * @default null
             */
            reason: string | null;
            requested_by: components["schemas"]["ActorRef"];
            /**
             * Run Id
             * Format: uuid
             */
            run_id: string;
            /** Step Key */
            step_key: string;
            /** Target */
            target: string;
        };
        /** Asset */
        Asset: {
            /**
             * Addresses
             * @default []
             */
            addresses: components["schemas"]["SiteScopedAddress"][];
            /** @default medium */
            criticality: components["schemas"]["Criticality"];
            /** Display Name */
            display_name: string;
            /** @default unknown */
            exposure: components["schemas"]["Exposure"];
            /**
             * Fqdns
             * @default []
             */
            fqdns: string[];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "host" | "domain" | "web_application" | "network_device" | "cloud_resource";
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /**
             * Sources
             * @default []
             */
            sources: components["schemas"]["AssetSourceLink"][];
            /**
             * Tags
             * @default []
             */
            tags: string[];
        };
        /** AssetAlertRef */
        AssetAlertRef: {
            /**
             * Case Id
             * @default null
             */
            case_id: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            /** Rule Description */
            rule_description: string;
            /** Rule Id */
            rule_id: string;
            /** Severity */
            severity: string;
            /** Source */
            source: string;
            /** Status */
            status: string;
        };
        /** AssetCaseRef */
        AssetCaseRef: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Reference */
            reference: string;
            /** Severity */
            severity: string;
            /** Status */
            status: string;
            /** Title */
            title: string;
        };
        /** AssetCreate */
        AssetCreate: {
            /**
             * Classification
             * @default unclassified
             * @enum {string}
             */
            classification: "server" | "workstation" | "network" | "domain" | "web" | "cloud" | "iot" | "unclassified";
            /**
             * Criticality
             * @default medium
             * @enum {string}
             */
            criticality: "low" | "medium" | "high" | "critical";
            /** Display Name */
            display_name: string;
            /**
             * Exposure
             * @default unknown
             * @enum {string}
             */
            exposure: "internet_facing" | "internal" | "unknown";
            /**
             * Fqdn
             * @default null
             */
            fqdn: string | null;
            /**
             * Hostname
             * @default null
             */
            hostname: string | null;
            /**
             * Ip
             * @default null
             */
            ip: string | null;
            /**
             * Kind
             * @enum {string}
             */
            kind: "host" | "domain" | "web_application" | "network_device" | "cloud_resource";
            /**
             * Owner
             * @default
             */
            owner: string;
            /**
             * Site Id
             * @default null
             */
            site_id: string | null;
            /**
             * Tags
             * @default []
             */
            tags: string[];
        };
        /** AssetDetail */
        AssetDetail: {
            /** Alerts */
            alerts: components["schemas"]["AssetAlertRef"][];
            asset: components["schemas"]["AssetSummary"];
            /** Cases */
            cases: components["schemas"]["AssetCaseRef"][];
            /**
             * Cnii
             * @default null
             */
            cnii: {
                [key: string]: unknown;
            } | null;
            /**
             * Detection Note
             * @description How Wazuh vulnerability detection and VMS findings relate on this asset
             */
            detection_note: string;
            /** Events */
            events: components["schemas"]["AssetEventView"][];
            /** Findings */
            findings: components["schemas"]["AssetFindingRef"][];
            /** Identifiers */
            identifiers: components["schemas"]["AssetIdentifierView"][];
            /** Intel */
            intel: components["schemas"]["AssetIntelRef"][];
            /**
             * Nhai Jobs
             * @default []
             */
            nhai_jobs: components["schemas"]["NhaiJob"][];
            /** Services */
            services: components["schemas"]["AssetServiceView"][];
            /** Soar Runs */
            soar_runs: components["schemas"]["AssetSoarRef"][];
            /** Trend */
            trend: components["schemas"]["AssetTrendPoint"][];
            /** @default null */
            wazuh: components["schemas"]["WazuhAgentContext"] | null;
        };
        /** AssetEventView */
        AssetEventView: {
            /** Actor Label */
            actor_label: string;
            /**
             * Details
             * @default {}
             */
            details: {
                [key: string]: unknown;
            };
            /** Id */
            id: number;
            /**
             * Kind
             * @enum {string}
             */
            kind: "discovered" | "identifier_added" | "identifier_conflict" | "updated" | "service_seen" | "merged" | "retired" | "reclassified";
            /**
             * Occurred At
             * Format: date-time
             */
            occurred_at: string;
            /** Source */
            source: string;
        };
        /** AssetFindingRef */
        AssetFindingRef: {
            /**
             * Cves
             * @default []
             */
            cves: string[];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            /**
             * Port
             * @default null
             */
            port: number | null;
            /** Priority */
            priority: string;
            /** Risk Score */
            risk_score: number;
            /** Severity */
            severity: string;
            /** Status */
            status: string;
            /** Title */
            title: string;
        };
        /** AssetIdentifierView */
        AssetIdentifierView: {
            /**
             * First Seen At
             * Format: date-time
             */
            first_seen_at: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "wazuh_agent" | "hostname" | "fqdn" | "ip" | "mac" | "domain" | "url" | "cloud_id" | "serial";
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            /**
             * Site Key
             * @default
             */
            site_key: string;
            /** Sources */
            sources: string[];
            /** Value */
            value: string;
        };
        /** AssetIntelRef */
        AssetIntelRef: {
            /**
             * Alert Id
             * Format: uuid
             */
            alert_id: string;
            /** Confidence */
            confidence: number;
            /** Indicator Type */
            indicator_type: string;
            /** Indicator Value */
            indicator_value: string;
            /**
             * Match Id
             * Format: uuid
             */
            match_id: string;
            /**
             * Matched At
             * Format: date-time
             */
            matched_at: string;
            /** Verdict */
            verdict: string;
        };
        /** AssetList */
        AssetList: {
            /**
             * By Criticality
             * @default {}
             */
            by_criticality: {
                [key: string]: number;
            };
            /**
             * By Kind
             * @default {}
             */
            by_kind: {
                [key: string]: number;
            };
            /**
             * By Monitoring
             * @default {}
             */
            by_monitoring: {
                [key: string]: number;
            };
            /** Items */
            items: components["schemas"]["AssetSummary"][];
            /** Limit */
            limit: number;
            /** Offset */
            offset: number;
            /** Total */
            total: number;
        };
        /**
         * AssetMerge
         * @description Merge `source_asset_id` INTO the asset in the path: identifiers, services, findings and alerts move; the source
         *     asset is retired with merged_into set. Audited; cannot be undone automatically.
         */
        AssetMerge: {
            /** Reason */
            reason: string;
            /**
             * Source Asset Id
             * Format: uuid
             */
            source_asset_id: string;
        };
        /** AssetMonitoring */
        AssetMonitoring: {
            /**
             * Cnii Designated
             * @default false
             */
            cnii_designated: boolean;
            /**
             * Last Vms Scan At
             * @default null
             */
            last_vms_scan_at: string | null;
            /**
             * State
             * @description monitored: a Wazuh agent AND a VMS scan in 30 days; partial: one of them; unmonitored: neither
             * @enum {string}
             */
            state: "monitored" | "partial" | "unmonitored";
            /**
             * Wazuh Agent Id
             * @default null
             */
            wazuh_agent_id: string | null;
        };
        /** AssetRetire */
        AssetRetire: {
            /** Reason */
            reason: string;
        };
        /** AssetServiceView */
        AssetServiceView: {
            /**
             * First Seen At
             * Format: date-time
             */
            first_seen_at: string;
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            /** Name */
            name: string;
            /** Port */
            port: number;
            /** Product */
            product: string;
            /** Protocol */
            protocol: string;
            /** Source */
            source: string;
            /** Version */
            version: string;
        };
        /** AssetSoarRef */
        AssetSoarRef: {
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Mode */
            mode: string;
            /** Playbook Name */
            playbook_name: string;
            /**
             * Run Id
             * Format: uuid
             */
            run_id: string;
            /** State */
            state: string;
        };
        /** AssetSourceLink */
        AssetSourceLink: {
            /**
             * External Id
             * @description e.g. Wazuh agent id '003' (unique per manager+org)
             */
            external_id: string;
            /**
             * First Seen At
             * Format: date-time
             */
            first_seen_at: string;
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            type: components["schemas"]["AssetSourceType"];
        };
        /**
         * AssetSourceType
         * @enum {string}
         */
        AssetSourceType: "wazuh_agent" | "scanner_observation" | "collector_discovery" | "import";
        /** AssetSummary */
        AssetSummary: {
            /**
             * Classification
             * @enum {string}
             */
            classification: "server" | "workstation" | "network" | "domain" | "web" | "cloud" | "iot" | "unclassified";
            /**
             * Critical Findings
             * @default 0
             */
            critical_findings: number;
            /**
             * Criticality
             * @enum {string}
             */
            criticality: "low" | "medium" | "high" | "critical";
            /** Display Name */
            display_name: string;
            /**
             * Exposure
             * @enum {string}
             */
            exposure: "internet_facing" | "internal" | "unknown";
            /**
             * First Seen At
             * Format: date-time
             */
            first_seen_at: string;
            /**
             * Fqdn
             * @default null
             */
            fqdn: string | null;
            /**
             * Hostname
             * @default null
             */
            hostname: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "host" | "domain" | "web_application" | "network_device" | "cloud_resource";
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            /**
             * Merged Into
             * @default null
             */
            merged_into: string | null;
            monitoring: components["schemas"]["AssetMonitoring"];
            /**
             * Open Alerts
             * @default 0
             */
            open_alerts: number;
            /**
             * Open Findings
             * @default 0
             */
            open_findings: number;
            /**
             * Os Name
             * @default null
             */
            os_name: string | null;
            /**
             * Os Platform
             * @default null
             */
            os_platform: string | null;
            /**
             * Os Version
             * @default null
             */
            os_version: string | null;
            /** Owner */
            owner: string;
            /**
             * Primary Ip
             * @default null
             */
            primary_ip: string | null;
            /**
             * Site Id
             * @default null
             */
            site_id: string | null;
            /**
             * Site Name
             * @default null
             */
            site_name: string | null;
            /**
             * Sources
             * @default []
             */
            sources: string[];
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "retired";
            /**
             * Tags
             * @default []
             */
            tags: string[];
        };
        /** AssetSummaryRequest */
        AssetSummaryRequest: {
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
        };
        /** AssetTrendPoint */
        AssetTrendPoint: {
            /** Alerts */
            alerts: number;
            /** New Findings */
            new_findings: number;
            /** Resolved Findings */
            resolved_findings: number;
            /**
             * Week Start
             * Format: date
             */
            week_start: string;
        };
        /** AssetUpdate */
        AssetUpdate: {
            /**
             * Classification
             * @default null
             */
            classification: ("server" | "workstation" | "network" | "domain" | "web" | "cloud" | "iot" | "unclassified") | null;
            /**
             * Criticality
             * @default null
             */
            criticality: ("low" | "medium" | "high" | "critical") | null;
            /**
             * Display Name
             * @default null
             */
            display_name: string | null;
            /**
             * Exposure
             * @default null
             */
            exposure: ("internet_facing" | "internal" | "unknown") | null;
            /**
             * Owner
             * @default null
             */
            owner: string | null;
            /**
             * Site Id
             * @default null
             */
            site_id: string | null;
            /**
             * Tags
             * @default null
             */
            tags: string[] | null;
        };
        /**
         * AssignmentRequest
         * @description Assign (or, with null, unassign) an alert or a case. The assignee must be a member of the organization.
         */
        AssignmentRequest: {
            /**
             * Assignee Id
             * @default null
             */
            assignee_id: string | null;
            /**
             * Note
             * @default
             */
            note: string;
        };
        /** AuditEvent */
        AuditEvent: {
            /** Action */
            action: string;
            /** Actor Id */
            actor_id: string | null;
            /** Actor Label */
            actor_label: string;
            /**
             * Actor Type
             * @enum {string}
             */
            actor_type: "user" | "service" | "system";
            /**
             * Details
             * @description Consolidation: the event's recorded details (never secrets)
             * @default {}
             */
            details: {
                [key: string]: unknown;
            };
            /** Id */
            id: number;
            /**
             * Occurred At
             * Format: date-time
             */
            occurred_at: string;
            /** Org Id */
            org_id: string | null;
            /**
             * Outcome
             * @enum {string}
             */
            outcome: "success" | "denied" | "failure";
            /** Request Id */
            request_id: string;
            /** Resource Id */
            resource_id: string;
            /** Resource Type */
            resource_type: string;
        };
        /** AuditEventList */
        AuditEventList: {
            /** Items */
            items: components["schemas"]["AuditEvent"][];
            /**
             * Total
             * @default null
             */
            total: number | null;
        };
        /**
         * BackupAgentReport
         * @description Backup agent -> API, authenticated by its service identity (replaces the unauthenticated legacy route).
         */
        BackupAgentReport: {
            job: components["schemas"]["BackupJob"];
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * Report Id
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            report_id: string;
        };
        /** BackupJob */
        BackupJob: {
            /**
             * Encrypted
             * @default true
             * @constant
             */
            encrypted: true;
            /**
             * Finished At
             * @default null
             */
            finished_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            kind: components["schemas"]["BackupKind"];
            /**
             * Sha256
             * @default null
             */
            sha256: string | null;
            /**
             * Size Bytes
             * @default null
             */
            size_bytes: number | null;
            /**
             * Started At
             * Format: date-time
             */
            started_at: string;
            /**
             * Status
             * @enum {string}
             */
            status: "running" | "succeeded" | "failed";
            /**
             * Target
             * @description External object-storage location label, never on Server 2
             */
            target: string;
        };
        /**
         * BackupKind
         * @enum {string}
         */
        BackupKind: "logical_dump" | "wal_archive";
        /** BackupRunList */
        BackupRunList: {
            /** Items */
            items: components["schemas"]["BackupRunView"][];
        };
        /** BackupRunView */
        BackupRunView: {
            /** Encrypted */
            encrypted: boolean;
            /**
             * Finished At
             * @default null
             */
            finished_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "logical_dump" | "wal_archive";
            /**
             * Last Drill At
             * @default null
             */
            last_drill_at: string | null;
            /**
             * Last Drill Status
             * @default null
             */
            last_drill_status: ("succeeded" | "failed") | null;
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * Sha256
             * @default null
             */
            sha256: string | null;
            /**
             * Size Bytes
             * @default null
             */
            size_bytes: number | null;
            /**
             * Started At
             * Format: date-time
             */
            started_at: string;
            /**
             * Status
             * @enum {string}
             */
            status: "running" | "succeeded" | "failed";
            /** Target */
            target: string;
        };
        /** BehaviouralInsightSummaryRequest */
        BehaviouralInsightSummaryRequest: {
            entity: components["schemas"]["ResourceRef"];
            /**
             * Window End
             * Format: date-time
             */
            window_end: string;
            /**
             * Window Start
             * Format: date-time
             */
            window_start: string;
        };
        /**
         * BehaviouralSignal
         * @description A deviation from the organisation's own baseline (behavioural analytics, BUILD LATER).
         */
        BehaviouralSignal: {
            /** Baseline */
            baseline: number;
            entity: components["schemas"]["ResourceRef"];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Metric */
            metric: string;
            /** Model Version */
            model_version: string;
            /** Observed */
            observed: number;
            /**
             * Window End
             * Format: date-time
             */
            window_end: string;
            /**
             * Window Start
             * Format: date-time
             */
            window_start: string;
        };
        /** BillingOverview */
        BillingOverview: {
            /** Note */
            note: string;
            /** Organizations */
            organizations: components["schemas"]["OrgBillingRow"][];
            /**
             * Payment Provider
             * @default not_configured
             * @constant
             */
            payment_provider: "not_configured";
            /** Plans */
            plans: components["schemas"]["BillingPlanView"][];
        };
        /** BillingPlanCreate */
        BillingPlanCreate: {
            /**
             * Billing Interval
             * @default monthly
             * @enum {string}
             */
            billing_interval: "monthly" | "annual";
            /** Code */
            code: string;
            /**
             * Currency
             * @default NGN
             */
            currency: string;
            /**
             * Description
             * @default
             */
            description: string;
            /**
             * Features
             * @default []
             */
            features: string[];
            /**
             * Max Assets
             * @default null
             */
            max_assets: number | null;
            /**
             * Max Users
             * @default null
             */
            max_users: number | null;
            /** Name */
            name: string;
            /**
             * Price Minor
             * @description Price in the currency's minor unit (kobo, cents)
             */
            price_minor: number;
        };
        /** BillingPlanUpdate */
        BillingPlanUpdate: {
            /** Active */
            active: boolean;
        };
        /** BillingPlanView */
        BillingPlanView: {
            /** Active */
            active: boolean;
            /**
             * Billing Interval
             * @default monthly
             * @enum {string}
             */
            billing_interval: "monthly" | "annual";
            /** Code */
            code: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Currency
             * @default NGN
             */
            currency: string;
            /**
             * Description
             * @default
             */
            description: string;
            /**
             * Features
             * @default []
             */
            features: string[];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Max Assets
             * @default null
             */
            max_assets: number | null;
            /**
             * Max Users
             * @default null
             */
            max_users: number | null;
            /** Name */
            name: string;
            /**
             * Price Minor
             * @description Price in the currency's minor unit (kobo, cents)
             */
            price_minor: number;
        };
        /** BrandFinding */
        BrandFinding: {
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            severity: components["schemas"]["Severity"];
            /**
             * Source
             * @description e.g. crtsh, rdap, app_store, code_search, leak_site
             */
            source: string;
            /**
             * Status
             * @enum {string}
             */
            status: "new" | "triaged" | "actioned" | "dismissed";
            /**
             * Subject Id
             * Format: uuid
             */
            subject_id: string;
            /** Summary */
            summary: string;
            /**
             * Url
             * @default null
             */
            url: string | null;
        };
        /** BrandFindingList */
        BrandFindingList: {
            /** Items */
            items: components["schemas"]["BrandFindingView"][];
        };
        /** BrandFindingTriage */
        BrandFindingTriage: {
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * Status
             * @enum {string}
             */
            status: "triaged" | "actioned" | "dismissed";
        };
        /** BrandFindingView */
        BrandFindingView: {
            /**
             * Evidence
             * @default {}
             */
            evidence: {
                [key: string]: unknown;
            };
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            severity: components["schemas"]["Severity"];
            /**
             * Source
             * @description e.g. crtsh, rdap, app_store, code_search, leak_site
             */
            source: string;
            /**
             * Status
             * @enum {string}
             */
            status: "new" | "triaged" | "actioned" | "dismissed";
            /**
             * Subject Id
             * Format: uuid
             */
            subject_id: string;
            /** Summary */
            summary: string;
            /**
             * Url
             * @default null
             */
            url: string | null;
            /** Value */
            value: string;
        };
        /**
         * Capability
         * @enum {string}
         */
        Capability: "syslog_receive" | "windows_event_forward" | "file_tail" | "network_discovery" | "scan_relay" | "wazuh_agent_bridge";
        /**
         * CaseAssistanceRequest
         * @description Investigation assistance for one case: its linked alerts (authoritative severities), notes, timeline and the
         *     Threat Insights matches of those alerts. A draft for the analyst; it never changes the case.
         */
        CaseAssistanceRequest: {
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
        };
        /** CaseDetail */
        CaseDetail: {
            /** Alert Count */
            alert_count: number;
            /** Alerts */
            alerts: components["schemas"]["StoredAlert"][];
            /**
             * Assignee Id
             * @default null
             */
            assignee_id: string | null;
            /**
             * Assignee Label
             * @default null
             */
            assignee_label: string | null;
            /**
             * Closed At
             * @default null
             */
            closed_at: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * First Response At
             * @default null
             */
            first_response_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Reference
             * @description Human reference, e.g. CASE-000042
             */
            reference: string;
            /**
             * Resolved At
             * @default null
             */
            resolved_at: string | null;
            severity: components["schemas"]["Severity"];
            /**
             * Sla Resolution Due At
             * @default null
             */
            sla_resolution_due_at: string | null;
            /**
             * Sla Response Due At
             * @description Consolidation: from the SLA policy when the case was created
             * @default null
             */
            sla_response_due_at: string | null;
            /**
             * Sla State
             * @default no_policy
             * @enum {string}
             */
            sla_state: "met" | "on_track" | "at_risk" | "breached" | "no_policy";
            /** Source */
            source: string;
            /**
             * Status
             * @enum {string}
             */
            status: "open" | "in_progress" | "resolved" | "closed";
            /** Timeline */
            timeline: components["schemas"]["CaseEvent"][];
            /** Title */
            title: string;
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** CaseEvent */
        CaseEvent: {
            /** Actor Label */
            actor_label: string;
            /** Body */
            body: string;
            /** Id */
            id: number;
            /**
             * Kind
             * @enum {string}
             */
            kind: "created" | "note" | "status_changed" | "alert_linked" | "assigned" | "remediation" | "evidence" | "sla_escalated" | "closure" | "severity_changed";
            /**
             * Occurred At
             * Format: date-time
             */
            occurred_at: string;
        };
        /** CaseList */
        CaseList: {
            /** Items */
            items: components["schemas"]["CaseSummary"][];
            /** Limit */
            limit: number;
            /** Offset */
            offset: number;
            /** Total */
            total: number;
        };
        /**
         * CaseNoteAcceptance
         * @description An analyst turns a draft into a real case note (possibly edited). Only this writes to the case.
         */
        CaseNoteAcceptance: {
            /** Final Body Markdown */
            final_body_markdown: string;
            /**
             * Result Id
             * Format: uuid
             */
            result_id: string;
            review: components["schemas"]["HumanReview"];
        };
        /** CaseNoteCreate */
        CaseNoteCreate: {
            /** Body */
            body: string;
            /**
             * Kind
             * @description Consolidation: remediation and evidence notes are typed timeline entries
             * @default note
             * @enum {string}
             */
            kind: "note" | "remediation" | "evidence";
        };
        /** CaseNoteDraft */
        CaseNoteDraft: {
            /** Body Markdown */
            body_markdown: string;
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /** Citations */
            citations: components["schemas"]["Citation"][];
            /**
             * Note Kind
             * @enum {string}
             */
            note_kind: "progress" | "handover" | "closure";
            /**
             * Result Id
             * Format: uuid
             */
            result_id: string;
        };
        /** CaseNoteDraftRequest */
        CaseNoteDraftRequest: {
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /**
             * Evidence Ids
             * @description Optional: limit the bundle to these case evidence items
             * @default []
             */
            evidence_ids: string[];
            /**
             * Note Kind
             * @enum {string}
             */
            note_kind: "progress" | "handover" | "closure";
        };
        /** CasePromotionResult */
        CasePromotionResult: {
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /**
             * Created
             * @description False when an existing case with the same dedupe key was returned
             */
            created: boolean;
            /** Linked Alert Ids */
            linked_alert_ids: string[];
        };
        /** CaseSlaView */
        CaseSlaView: {
            /**
             * Assignee Label
             * @default null
             */
            assignee_label: string | null;
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Escalated At
             * @default null
             */
            escalated_at: string | null;
            /**
             * First Response At
             * @default null
             */
            first_response_at: string | null;
            /** Reference */
            reference: string;
            /**
             * Resolution Due At
             * @default null
             */
            resolution_due_at: string | null;
            /**
             * Resolution State
             * @enum {string}
             */
            resolution_state: "met" | "on_track" | "at_risk" | "breached" | "no_policy";
            /**
             * Resolved At
             * @default null
             */
            resolved_at: string | null;
            /**
             * Response Due At
             * @default null
             */
            response_due_at: string | null;
            /**
             * Response State
             * @enum {string}
             */
            response_state: "met" | "on_track" | "at_risk" | "breached" | "no_policy";
            /**
             * Severity
             * @enum {string}
             */
            severity: "critical" | "high" | "medium" | "low";
            /** Status */
            status: string;
            /** Title */
            title: string;
        };
        /** CaseStatusUpdate */
        CaseStatusUpdate: {
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * Status
             * @enum {string}
             */
            status: "open" | "in_progress" | "resolved" | "closed";
        };
        /** CaseSummary */
        CaseSummary: {
            /** Alert Count */
            alert_count: number;
            /**
             * Assignee Id
             * @default null
             */
            assignee_id: string | null;
            /**
             * Assignee Label
             * @default null
             */
            assignee_label: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * First Response At
             * @default null
             */
            first_response_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Reference
             * @description Human reference, e.g. CASE-000042
             */
            reference: string;
            /**
             * Resolved At
             * @default null
             */
            resolved_at: string | null;
            severity: components["schemas"]["Severity"];
            /**
             * Sla Resolution Due At
             * @default null
             */
            sla_resolution_due_at: string | null;
            /**
             * Sla Response Due At
             * @description Consolidation: from the SLA policy when the case was created
             * @default null
             */
            sla_response_due_at: string | null;
            /**
             * Sla State
             * @default no_policy
             * @enum {string}
             */
            sla_state: "met" | "on_track" | "at_risk" | "breached" | "no_policy";
            /** Source */
            source: string;
            /**
             * Status
             * @enum {string}
             */
            status: "open" | "in_progress" | "resolved" | "closed";
            /** Title */
            title: string;
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** ChatCitation */
        ChatCitation: {
            /** Citation Id */
            citation_id: string;
            /** Excerpt */
            excerpt: string;
            /**
             * Href
             * @default
             */
            href: string;
            /** Label */
            label: string;
            ref: components["schemas"]["ResourceRef"];
        };
        /** ChatConversationCreate */
        ChatConversationCreate: {
            /**
             * Title
             * @default New conversation
             */
            title: string;
        };
        /** ChatConversationList */
        ChatConversationList: {
            /** Items */
            items: components["schemas"]["ChatConversationView"][];
        };
        /** ChatConversationView */
        ChatConversationView: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Messages
             * @default []
             */
            messages: components["schemas"]["ChatMessageView"][];
            /** Title */
            title: string;
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** ChatExchange */
        ChatExchange: {
            answer: components["schemas"]["ChatMessageView"];
            question: components["schemas"]["ChatMessageView"];
        };
        /** ChatMessageCreate */
        ChatMessageCreate: {
            /** Content */
            content: string;
        };
        /** ChatMessageView */
        ChatMessageView: {
            /**
             * Citations
             * @default []
             */
            citations: components["schemas"]["ChatCitation"][];
            /** Content */
            content: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * @description The AI-drafted answer job, when NHAI is configured
             * @default null
             */
            nhai: components["schemas"]["NhaiJob"] | null;
            /**
             * Role
             * @enum {string}
             */
            role: "user" | "assistant";
            /**
             * State
             * @enum {string}
             */
            state: "complete" | "refused";
            /**
             * Tools
             * @default []
             */
            tools: components["schemas"]["ChatToolCall"][];
        };
        /** ChatToolCall */
        ChatToolCall: {
            /**
             * Detail
             * @default
             */
            detail: string;
            /** Permission */
            permission: string;
            /**
             * Records
             * @default 0
             */
            records: number;
            /**
             * State
             * @enum {string}
             */
            state: "ok" | "empty" | "not_permitted" | "unavailable";
            /** Tool */
            tool: string;
        };
        /** ChatTurn */
        ChatTurn: {
            /** Content */
            content: string;
            /**
             * Role
             * @enum {string}
             */
            role: "system" | "user" | "assistant";
        };
        /** Citation */
        Citation: {
            /**
             * Citation Id
             * @description Evidence key within one bundle
             */
            citation_id: string;
            /** Excerpt */
            excerpt: string;
            ref: components["schemas"]["ResourceRef"];
        };
        /** CniiAccessResponse */
        CniiAccessResponse: {
            /**
             * Active Org Id
             * Format: uuid
             */
            active_org_id: string;
            /**
             * Designation Id
             * Format: uuid
             */
            designation_id: string;
            /**
             * Note
             * @default Access check only. CNII data endpoints are not built in Phase 2.
             */
            note: string;
            /** Sector */
            sector: string;
        };
        /**
         * CniiAuthorizationCreate
         * @description The record that authorizes monitoring of designated CNII assets. Without an active one, nothing is monitored.
         */
        CniiAuthorizationCreate: {
            /**
             * Document Sha256
             * @default null
             */
            document_sha256: string | null;
            /** Issuing Authority */
            issuing_authority: string;
            /** Reference */
            reference: string;
            /** Scope Description */
            scope_description: string;
            /** Sectors */
            sectors: ("power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines")[];
            /**
             * Valid From
             * Format: date-time
             */
            valid_from: string;
            /**
             * Valid Until
             * Format: date-time
             */
            valid_until: string;
        };
        /** CniiAuthorizationList */
        CniiAuthorizationList: {
            /** Items */
            items: components["schemas"]["CniiAuthorizationView"][];
        };
        /** CniiAuthorizationRevoke */
        CniiAuthorizationRevoke: {
            /** Reason */
            reason: string;
        };
        /** CniiAuthorizationView */
        CniiAuthorizationView: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Document Sha256
             * @default null
             */
            document_sha256: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Issuing Authority */
            issuing_authority: string;
            /**
             * Monitored Assets
             * @default 0
             */
            monitored_assets: number;
            /** Recorded By */
            recorded_by: string;
            /** Reference */
            reference: string;
            /**
             * Revoked At
             * @default null
             */
            revoked_at: string | null;
            /**
             * Revoked Reason
             * @default null
             */
            revoked_reason: string | null;
            /** Scope Description */
            scope_description: string;
            /** Sectors */
            sectors: ("power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines")[];
            /**
             * State
             * @enum {string}
             */
            state: "active" | "not_yet_valid" | "expired" | "revoked";
            /**
             * Valid From
             * Format: date-time
             */
            valid_from: string;
            /**
             * Valid Until
             * Format: date-time
             */
            valid_until: string;
        };
        /** CniiCheckView */
        CniiCheckView: {
            /** Detail */
            detail: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "availability" | "vulnerability_scan";
            /**
             * Latency Ms
             * @default null
             */
            latency_ms: number | null;
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            /**
             * Outcome
             * @enum {string}
             */
            outcome: "up" | "down" | "degraded" | "not_run";
            /** Source */
            source: string;
        };
        /** CniiDesignation */
        CniiDesignation: {
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /**
             * Granted At
             * Format: date-time
             */
            granted_at: string;
            /**
             * Granted By
             * Format: uuid
             */
            granted_by: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Revoked At
             * @default null
             */
            revoked_at: string | null;
            /** Scope Org Ids */
            scope_org_ids: string[] | null;
            /** Sectors */
            sectors: ("power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines")[];
            /**
             * User Id
             * Format: uuid
             */
            user_id: string;
        };
        /**
         * CniiDesignationGrant
         * @description Granted by a super_admin (platform). Audited. Always expires.
         */
        CniiDesignationGrant: {
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /** Reason */
            reason: string;
            /**
             * Scope Org Ids
             * @description None = every organisation in those sectors
             * @default null
             */
            scope_org_ids: string[] | null;
            /** Sectors */
            sectors: ("power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines")[];
            /**
             * User Id
             * Format: uuid
             */
            user_id: string;
        };
        /** CniiDesignationList */
        CniiDesignationList: {
            /** Items */
            items: components["schemas"]["CniiDesignation"][];
        };
        /** CniiDesignationRevoke */
        CniiDesignationRevoke: {
            /**
             * Designation Id
             * Format: uuid
             */
            designation_id: string;
            /** Reason */
            reason: string;
        };
        /** CniiMonitoredAssetCreate */
        CniiMonitoredAssetCreate: {
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
            /**
             * Authorization Id
             * Format: uuid
             */
            authorization_id: string;
            /**
             * Monitoring
             * @default both
             * @enum {string}
             */
            monitoring: "availability" | "vulnerability" | "both";
            /** Owning Unit */
            owning_unit: string;
            /**
             * Sector
             * @enum {string}
             */
            sector: "power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines";
        };
        /** CniiMonitoredAssetList */
        CniiMonitoredAssetList: {
            /** Items */
            items: components["schemas"]["CniiMonitoredAssetView"][];
        };
        /** CniiMonitoredAssetStatus */
        CniiMonitoredAssetStatus: {
            /** Reason */
            reason: string;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "suspended";
        };
        /** CniiMonitoredAssetView */
        CniiMonitoredAssetView: {
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
            /** Asset Kind */
            asset_kind: string;
            /** Asset Name */
            asset_name: string;
            /**
             * Authorization Id
             * Format: uuid
             */
            authorization_id: string;
            /** Authorization Reference */
            authorization_reference: string;
            /**
             * Authorization State
             * @enum {string}
             */
            authorization_state: "active" | "not_yet_valid" | "expired" | "revoked";
            /**
             * Availability 30D
             * @description Share of recorded availability checks that were up; None when no check was recorded
             * @default null
             */
            availability_30d: number | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Critical Findings */
            critical_findings: number;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** @default null */
            last_check: components["schemas"]["CniiCheckView"] | null;
            /**
             * Monitoring
             * @enum {string}
             */
            monitoring: "availability" | "vulnerability" | "both";
            /** Open Findings */
            open_findings: number;
            /** Owning Unit */
            owning_unit: string;
            /**
             * Schedules
             * @default []
             */
            schedules: components["schemas"]["CniiScheduleView"][];
            /**
             * Sector
             * @enum {string}
             */
            sector: "power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines";
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "suspended";
        };
        /** CniiOrgProfile */
        CniiOrgProfile: {
            /**
             * Criticality
             * @enum {string}
             */
            criticality: "vital" | "high" | "moderate";
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /** Org Name */
            org_name: string;
            /** Sectors */
            sectors: ("power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines")[];
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** CniiOrgProfileList */
        CniiOrgProfileList: {
            /** Items */
            items: components["schemas"]["CniiOrgProfile"][];
        };
        /** CniiOrgProfileSet */
        CniiOrgProfileSet: {
            /**
             * Criticality
             * @enum {string}
             */
            criticality: "vital" | "high" | "moderate";
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /** Sectors */
            sectors: ("power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines")[];
        };
        /** CniiOverview */
        CniiOverview: {
            /** Authorizations Active */
            authorizations_active: number;
            /** Authorizations Expiring 30D */
            authorizations_expiring_30d: number;
            /** Availability Checks 30D */
            availability_checks_30d: number;
            /** By Sector */
            by_sector: {
                [key: string]: number;
            };
            /** Critical Findings */
            critical_findings: number;
            /** Designation Sectors */
            designation_sectors: ("power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines")[];
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Monitored Assets */
            monitored_assets: number;
            /** Open Findings */
            open_findings: number;
            /**
             * Probe
             * @description Whether an availability probe is configured in this installation
             */
            probe: string;
            /** Suspended Assets */
            suspended_assets: number;
        };
        /** CniiScheduleSet */
        CniiScheduleSet: {
            /**
             * Check Kind
             * @enum {string}
             */
            check_kind: "availability" | "vulnerability_scan";
            /**
             * Enabled
             * @default false
             */
            enabled: boolean;
            /** Interval Minutes */
            interval_minutes: number;
        };
        /** CniiScheduleView */
        CniiScheduleView: {
            /**
             * Check Kind
             * @enum {string}
             */
            check_kind: "availability" | "vulnerability_scan";
            /** Enabled */
            enabled: boolean;
            /** Execution */
            execution: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Interval Minutes */
            interval_minutes: number;
            /**
             * Last Run At
             * @default null
             */
            last_run_at: string | null;
            /**
             * Next Due At
             * @default null
             */
            next_due_at: string | null;
        };
        /** CniiSectorOverview */
        CniiSectorOverview: {
            /**
             * Designation Expires At
             * Format: date-time
             */
            designation_expires_at: string;
            /**
             * Designation Id
             * Format: uuid
             */
            designation_id: string;
            /** Items */
            items: components["schemas"]["CniiSectorRow"][];
            /**
             * Sector
             * @enum {string}
             */
            sector: "power" | "water" | "ict" | "finance" | "health" | "publicadmin" | "education" | "defence" | "transport" | "food" | "safety" | "industrial" | "mines";
        };
        /** CniiSectorRow */
        CniiSectorRow: {
            /** Critical Alerts 7D */
            critical_alerts_7d: number;
            /**
             * Criticality
             * @enum {string}
             */
            criticality: "vital" | "high" | "moderate";
            /** Open Alerts */
            open_alerts: number;
            /** Open Cases */
            open_cases: number;
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /** Org Name */
            org_name: string;
        };
        /** CollectorConfig */
        CollectorConfig: {
            /** Config Version */
            config_version: number;
            /**
             * Issued At
             * Format: date-time
             */
            issued_at: string;
            /**
             * Signature
             * @description Detached signature over the canonical JSON of this document (algorithm per ADR)
             */
            signature: string;
            /** Sources */
            sources: components["schemas"]["SourceDefinition"][];
            /**
             * Telemetry Max Batch
             * @default 500
             */
            telemetry_max_batch: number;
            /**
             * Telemetry Max Rate Per Minute
             * @default 60000
             */
            telemetry_max_rate_per_minute: number;
        };
        /** CollectorCreate */
        CollectorCreate: {
            /**
             * Authorization Reference
             * @default
             */
            authorization_reference: string;
            /**
             * Interval Minutes
             * @default 1440
             */
            interval_minutes: number;
            /**
             * Kind
             * @enum {string}
             */
            kind: "wazuh_sync" | "network_discovery" | "cloud_inventory" | "manual_import";
            /** Name */
            name: string;
            /**
             * Settings
             * @default {}
             */
            settings: {
                [key: string]: string | number | boolean | string[];
            };
            /**
             * Site Id
             * @default null
             */
            site_id: string | null;
        };
        /**
         * CollectorHealth
         * @enum {string}
         */
        CollectorHealth: "ok" | "degraded" | "failing";
        /** CollectorHeartbeat */
        CollectorHeartbeat: {
            /** Collector Version */
            collector_version: string;
            /** Config Version */
            config_version: number;
            /**
             * Dropped Since Last
             * @default 0
             */
            dropped_since_last: number;
            health: components["schemas"]["CollectorHealth"];
            /**
             * Problems
             * @default []
             */
            problems: string[];
            /** Queue Depth */
            queue_depth: number;
            /**
             * Sent At
             * Format: date-time
             */
            sent_at: string;
            /**
             * Sources Active
             * @default 0
             */
            sources_active: number;
        };
        /** CollectorList */
        CollectorList: {
            /** Items */
            items: components["schemas"]["CollectorView"][];
        };
        /**
         * CollectorRecord
         * @description Stored view of a collector (internal; org_id is the identity's, never client-supplied).
         */
        CollectorRecord: {
            /** Capabilities */
            capabilities: components["schemas"]["Capability"][];
            /**
             * Identity Id
             * Format: uuid
             */
            identity_id: string;
            /**
             * Last Heartbeat At
             * @default null
             */
            last_heartbeat_at: string | null;
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /**
             * Site Id
             * Format: uuid
             */
            site_id: string;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "revoked";
        };
        /** CollectorUpdate */
        CollectorUpdate: {
            /**
             * Authorization Reference
             * @default null
             */
            authorization_reference: string | null;
            /**
             * Enabled
             * @default null
             */
            enabled: boolean | null;
            /**
             * Interval Minutes
             * @default null
             */
            interval_minutes: number | null;
            /**
             * Settings
             * @default null
             */
            settings: {
                [key: string]: string | number | boolean | string[];
            } | null;
        };
        /** CollectorView */
        CollectorView: {
            /** Authorization Reference */
            authorization_reference: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Enabled */
            enabled: boolean;
            /**
             * Execution
             * @description What actually runs for this collector in this installation
             */
            execution: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Interval Minutes */
            interval_minutes: number;
            /**
             * Kind
             * @enum {string}
             */
            kind: "wazuh_sync" | "network_discovery" | "cloud_inventory" | "manual_import";
            /**
             * Last Outcome
             * @default null
             */
            last_outcome: string | null;
            /**
             * Last Run At
             * @default null
             */
            last_run_at: string | null;
            /** Name */
            name: string;
            /**
             * Settings
             * @default {}
             */
            settings: {
                [key: string]: unknown;
            };
            /**
             * Site Id
             * @default null
             */
            site_id: string | null;
        };
        /** CommandList */
        CommandList: {
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Items */
            items: components["schemas"]["CommandRecord"][];
            /**
             * Per Organization
             * @description Records returned per organization slug (before the overall limit)
             */
            per_organization: {
                [key: string]: number;
            };
            /**
             * Truncated
             * @description True when an organization had more matching records than were read
             */
            truncated: boolean;
            /**
             * View
             * @enum {string}
             */
            view: "assets" | "alerts" | "vulnerabilities" | "scans" | "cases" | "intel" | "nhai" | "soar_runs" | "soar_approvals" | "reports";
        };
        /** CommandOrg */
        CommandOrg: {
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "platform" | "client";
            /** Name */
            name: string;
            /** Slug */
            slug: string;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "suspended" | "archived";
        };
        /** CommandOverview */
        CommandOverview: {
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Organizations */
            organizations: components["schemas"]["OrgPosture"][];
            /**
             * Scope
             * @enum {string}
             */
            scope: "platform" | "assigned";
            /** Totals */
            totals: {
                [key: string]: number;
            };
        };
        /**
         * CommandRecord
         * @description One tenant-owned record, labelled with its owner. `fields` holds the view's columns (documented per view).
         */
        CommandRecord: {
            /**
             * At
             * @default null
             */
            at: string | null;
            /**
             * Fields
             * @default {}
             */
            fields: {
                [key: string]: unknown;
            };
            /** Id */
            id: string;
            org: components["schemas"]["CommandOrg"];
            /**
             * Severity
             * @default null
             */
            severity: string | null;
            /**
             * Status
             * @default null
             */
            status: string | null;
            /** Title */
            title: string;
        };
        /** CommandScope */
        CommandScope: {
            /** Can Export */
            can_export: boolean;
            /** Organizations */
            organizations: components["schemas"]["CommandOrg"][];
            /**
             * Scope
             * @description platform: every organization; assigned: home + operations assignments
             * @enum {string}
             */
            scope: "platform" | "assigned";
            /**
             * Views
             * @description The views this person's permissions allow
             */
            views: ("assets" | "alerts" | "vulnerabilities" | "scans" | "cases" | "intel" | "nhai" | "soar_runs" | "soar_approvals" | "reports")[];
        };
        /** CompliancePolicyRow */
        CompliancePolicyRow: {
            /**
             * Average Score
             * @default null
             */
            average_score: number | null;
            /** Endpoints */
            endpoints: number;
            /** Failed Checks */
            failed_checks: number;
            /** Name */
            name: string;
            /** Passed Checks */
            passed_checks: number;
            /** Policy Id */
            policy_id: string;
        };
        /** ComplianceView */
        ComplianceView: {
            /**
             * Endpoints Assessed
             * @default 0
             */
            endpoints_assessed: number;
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * Policies
             * @default []
             */
            policies: components["schemas"]["CompliancePolicyRow"][];
            source: components["schemas"]["ConnectorState"];
        };
        /** ComponentHealth */
        ComponentHealth: {
            /**
             * Checked At
             * @default null
             */
            checked_at: string | null;
            /** Detail */
            detail: string;
            /** Key */
            key: string;
            /** Label */
            label: string;
            /**
             * State
             * @enum {string}
             */
            state: "ok" | "degraded" | "failing" | "unconfigured" | "unknown";
        };
        /**
         * ComponentHeartbeat
         * @description Sent by a background component every <= 60 s. Identity (and organisation, for tenant-bound
         *     components) comes from the authenticated machine credential.
         */
        ComponentHeartbeat: {
            /** Component Version */
            component_version: string;
            /**
             * Dependencies
             * @default []
             */
            dependencies: components["schemas"]["DependencyCheck"][];
            /**
             * In Flight
             * @default 0
             */
            in_flight: number;
            /**
             * Queue Depth
             * @default 0
             */
            queue_depth: number;
            /**
             * Sent At
             * Format: date-time
             */
            sent_at: string;
            state: components["schemas"]["HealthState"];
        };
        /**
         * ComponentKind
         * @enum {string}
         */
        ComponentKind: "api" | "vms_worker" | "soar_worker" | "forwarder" | "collector" | "job_runner" | "backup_agent" | "ai_gateway";
        /**
         * ComponentStatus
         * @description Read model for Platform Health. `stale` when no heartbeat arrived within 3 intervals.
         */
        ComponentStatus: {
            component: components["schemas"]["ComponentKind"];
            /**
             * Dependencies
             * @default []
             */
            dependencies: components["schemas"]["DependencyCheck"][];
            /**
             * Identity Id
             * @default null
             */
            identity_id: string | null;
            /**
             * Last Heartbeat At
             * @default null
             */
            last_heartbeat_at: string | null;
            /** State */
            state: components["schemas"]["HealthState"] | ("stale" | "never_seen");
            /**
             * Version
             * @default null
             */
            version: string | null;
        };
        /** ConflictList */
        ConflictList: {
            /** Items */
            items: components["schemas"]["ConflictView"][];
        };
        /** ConflictView */
        ConflictView: {
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
            /** Asset Name */
            asset_name: string;
            /**
             * Bound To Asset Id
             * @default null
             */
            bound_to_asset_id: string | null;
            /**
             * Bound To Asset Name
             * @default null
             */
            bound_to_asset_name: string | null;
            /** Event Id */
            event_id: number;
            /** Identifier Kind */
            identifier_kind: string;
            /** Identifier Value */
            identifier_value: string;
            /**
             * Occurred At
             * Format: date-time
             */
            occurred_at: string;
            /** Source */
            source: string;
        };
        /**
         * ConnectorState
         * @description State of one internal connector, as established by the API. Never claims a connection it has not made.
         */
        ConnectorState: {
            /**
             * Checked At
             * @description When reachability was last checked; null = never
             * @default null
             */
            checked_at: string | null;
            /**
             * Connector
             * @enum {string}
             */
            connector: "wazuh_manager" | "wazuh_indexer" | "ollama";
            /**
             * Detail
             * @default
             */
            detail: string;
            /**
             * State
             * @enum {string}
             */
            state: "unconfigured" | "local_fixture" | "connected" | "unavailable" | "error";
        };
        /**
         * ContextBundle
         * @description What the model sees. Never crosses organisations; sent only to the local inference backend.
         */
        ContextBundle: {
            /**
             * Assembled At
             * Format: date-time
             */
            assembled_at: string;
            /**
             * Assembled For
             * Format: uuid
             * @description The requesting user (audit)
             */
            assembled_for: string;
            /**
             * Bundle Id
             * Format: uuid
             */
            bundle_id: string;
            /** Evidence */
            evidence: components["schemas"]["EvidenceItem"][];
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            subject: components["schemas"]["ResourceRef"];
            task: components["schemas"]["NhaiTask"];
        };
        /** ContinuityOverview */
        ContinuityOverview: {
            /** Completed Requests */
            completed_requests: number;
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Not Recoverable */
            not_recoverable: number;
            /** Open Requests */
            open_requests: number;
            /** Plans */
            plans: number;
            /** Plans Untested 90D */
            plans_untested_90d: number;
            platform_backups: components["schemas"]["PlatformBackupState"];
            /** Rpo Met */
            rpo_met: number;
            /** Rpo Missed */
            rpo_missed: number;
            /** Rto Met */
            rto_met: number;
            /** Rto Missed */
            rto_missed: number;
        };
        /** ControlArea */
        ControlArea: {
            /** Description */
            description: string;
            /** Key */
            key: string;
            /** Measures */
            measures: components["schemas"]["Measure"][];
            /** Title */
            title: string;
        };
        /**
         * CorrelationGroup
         * @description Alerts of ONE organization that share a basis within a window.
         */
        CorrelationGroup: {
            /** Alert Ids */
            alert_ids: string[];
            /**
             * Basis
             * @enum {string}
             */
            basis: "shared_observable" | "same_agent_and_rule";
            /**
             * First Seen At
             * Format: date-time
             */
            first_seen_at: string;
            /** Key */
            key: string;
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            max_severity: components["schemas"]["Severity"];
        };
        /** CorrelationList */
        CorrelationList: {
            /** Items */
            items: components["schemas"]["CorrelationGroup"][];
            /** Window Hours */
            window_hours: number;
        };
        /**
         * CredentialRevocation
         * @description Operator action (human API). Effective immediately; audited.
         */
        CredentialRevocation: {
            /**
             * Identity Id
             * Format: uuid
             */
            identity_id: string;
            /** Reason */
            reason: string;
        };
        /** CredentialRotationRequest */
        CredentialRotationRequest: {
            /**
             * Request Id
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            request_id: string;
        };
        /** CredentialRotationResponse */
        CredentialRotationResponse: {
            /** Machine Credential */
            machine_credential: string;
            /**
             * Previous Valid Until
             * Format: date-time
             * @description Overlap window; the old credential stops working after this
             */
            previous_valid_until: string;
        };
        /**
         * Criticality
         * @enum {string}
         */
        Criticality: "low" | "medium" | "high" | "critical";
        /**
         * CveImport
         * @description Import CVE intelligence from a file the analyst obtained (records, or a CISA KEV catalog JSON document).
         *     NovrSOC does not fetch feeds itself here; the Server 1 feeder can deliver STIX vulnerabilities.
         */
        CveImport: {
            /**
             * Kev Catalog
             * @default null
             */
            kev_catalog: {
                [key: string]: unknown;
            } | null;
            /**
             * Records
             * @default []
             */
            records: components["schemas"]["CveRecordIn"][];
            /** Source */
            source: string;
        };
        /** CveImportResult */
        CveImportResult: {
            /** Imported */
            imported: number;
            /**
             * Skipped
             * @default []
             */
            skipped: string[];
        };
        /** CveIntelList */
        CveIntelList: {
            /**
             * Finding Cves Without Intel
             * @description CVEs in open findings with no intelligence record
             * @default []
             */
            finding_cves_without_intel: string[];
            /** Items */
            items: components["schemas"]["CveIntelView"][];
        };
        /** CveIntelView */
        CveIntelView: {
            /**
             * Actors
             * @description Actors linked to the CVE in this organization, with their association
             * @default []
             */
            actors: string[];
            /** Affected Assets */
            affected_assets: number;
            /**
             * Captured At
             * Format: date-time
             */
            captured_at: string;
            /** Cve Id */
            cve_id: string;
            /**
             * Cvss V3
             * @default null
             */
            cvss_v3: number | null;
            /**
             * Cvss Vector
             * @default null
             */
            cvss_vector: string | null;
            /** Description */
            description: string;
            /**
             * Epss
             * @default null
             */
            epss: number | null;
            /** Kev */
            kev: boolean;
            /**
             * Kev Added
             * @default null
             */
            kev_added: string | null;
            /**
             * Open Findings
             * @description This organization's open VMS findings that name the CVE
             */
            open_findings: number;
            /**
             * Published
             * @default null
             */
            published: string | null;
            /** Snapshots */
            snapshots: number;
            /** Source */
            source: string;
        };
        /** CveRecordIn */
        CveRecordIn: {
            /** Cve Id */
            cve_id: string;
            /**
             * Cvss V3
             * @default null
             */
            cvss_v3: number | null;
            /**
             * Cvss Vector
             * @default null
             */
            cvss_vector: string | null;
            /**
             * Description
             * @default
             */
            description: string;
            /**
             * Epss
             * @default null
             */
            epss: number | null;
            /**
             * Kev
             * @default false
             */
            kev: boolean;
            /**
             * Kev Added
             * @default null
             */
            kev_added: string | null;
            /**
             * Published
             * @default null
             */
            published: string | null;
        };
        /** DataExportCreate */
        DataExportCreate: {
            /**
             * Dataset
             * @enum {string}
             */
            dataset: "alerts" | "cases" | "vms_findings" | "assets" | "audit_events" | "ti_indicators";
            /**
             * Expires In Days
             * @default 7
             */
            expires_in_days: number;
            /**
             * Format
             * @default csv
             * @enum {string}
             */
            format: "csv" | "json";
            /** Justification */
            justification: string;
            /**
             * Period End
             * Format: date-time
             */
            period_end: string;
            /**
             * Period Start
             * Format: date-time
             */
            period_start: string;
            /**
             * Recipient
             * @description Who receives the export (organization or role)
             */
            recipient: string;
        };
        /** DataExportList */
        DataExportList: {
            /** Items */
            items: components["schemas"]["DataExportView"][];
            /** Max Rows */
            max_rows: number;
        };
        /** DataExportView */
        DataExportView: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Dataset
             * @enum {string}
             */
            dataset: "alerts" | "cases" | "vms_findings" | "assets" | "audit_events" | "ti_indicators";
            /** Downloads */
            downloads: number;
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /**
             * Format
             * @enum {string}
             */
            format: "csv" | "json";
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Justification */
            justification: string;
            /**
             * Period End
             * Format: date-time
             */
            period_end: string;
            /**
             * Period Start
             * Format: date-time
             */
            period_start: string;
            /** Recipient */
            recipient: string;
            requested_by: components["schemas"]["ActorRef"];
            /** Row Count */
            row_count: number;
            /** Sha256 */
            sha256: string;
            /**
             * State
             * @enum {string}
             */
            state: "available" | "expired" | "revoked";
            /** Truncated */
            truncated: boolean;
        };
        /** DependencyCheck */
        DependencyCheck: {
            /**
             * Detail
             * @description Never a secret, URL with credentials, or raw response body
             * @default
             */
            detail: string;
            /** Name */
            name: string;
            state: components["schemas"]["HealthState"];
        };
        /** DiscoveredHost */
        DiscoveredHost: {
            address: components["schemas"]["SiteScopedAddress"];
            /**
             * Mac
             * @default null
             */
            mac: string | null;
            /**
             * Method
             * @enum {string}
             */
            method: "arp" | "icmp" | "tcp_connect" | "passive";
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            /**
             * Open Ports
             * @default []
             */
            open_ports: number[];
        };
        /** DiscoveryReport */
        DiscoveryReport: {
            /** Hosts */
            hosts: components["schemas"]["DiscoveredHost"][];
            /**
             * Report Id
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            report_id: string;
        };
        /** DmarcAggregateReport */
        DmarcAggregateReport: {
            /**
             * Domain Id
             * Format: uuid
             */
            domain_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Messages Failing */
            messages_failing: number;
            /** Messages Total */
            messages_total: number;
            /**
             * Period End
             * Format: date-time
             */
            period_end: string;
            /**
             * Period Start
             * Format: date-time
             */
            period_start: string;
            /** Report Id */
            report_id: string;
            /** Reporter */
            reporter: string;
        };
        /** DmarcRecord */
        DmarcRecord: {
            /** Count */
            count: number;
            /** Disposition */
            disposition: string;
            /** Dkim */
            dkim: string;
            /** Header From */
            header_from: string;
            /** Source Ip */
            source_ip: string;
            /** Spf */
            spf: string;
        };
        /** DmarcReportList */
        DmarcReportList: {
            /** Items */
            items: components["schemas"]["DmarcReportView"][];
        };
        /** DmarcReportView */
        DmarcReportView: {
            /** Domain */
            domain: string;
            /**
             * Domain Id
             * Format: uuid
             */
            domain_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Messages Failing */
            messages_failing: number;
            /** Messages Total */
            messages_total: number;
            /**
             * Period End
             * Format: date-time
             */
            period_end: string;
            /**
             * Period Start
             * Format: date-time
             */
            period_start: string;
            /**
             * Published Policy
             * @default null
             */
            published_policy: string | null;
            /**
             * Records
             * @default []
             */
            records: components["schemas"]["DmarcRecord"][];
            /** Report Id */
            report_id: string;
            /** Reporter */
            reporter: string;
            /** Source */
            source: string;
        };
        /**
         * DmarcUpload
         * @description An aggregate (RUA) report as XML text, uploaded by a user or the test adapter. DTDs and entities are refused.
         */
        DmarcUpload: {
            /**
             * Source
             * @default upload
             */
            source: string;
            /** Xml */
            xml: string;
        };
        /** EmailDomain */
        EmailDomain: {
            /**
             * Dkim Selectors Found
             * @default []
             */
            dkim_selectors_found: string[];
            /**
             * Dmarc Policy
             * @default null
             */
            dmarc_policy: ("none" | "quarantine" | "reject" | "missing") | null;
            /** Domain */
            domain: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Last Checked At
             * @default null
             */
            last_checked_at: string | null;
            /**
             * Spf Valid
             * @default null
             */
            spf_valid: boolean | null;
            /**
             * Verification
             * @enum {string}
             */
            verification: "pending" | "verified" | "failed";
            /** Verification Txt Name */
            verification_txt_name: string;
        };
        /** EmailDomainCreate */
        EmailDomainCreate: {
            /** Domain */
            domain: string;
        };
        /** EmailDomainList */
        EmailDomainList: {
            /** Items */
            items: components["schemas"]["EmailDomain"][];
        };
        /**
         * EmergencyStopRequest
         * @description Turn the organization's emergency stop on or off (soar:manage). Always audited, always with a reason.
         */
        EmergencyStopRequest: {
            /** Active */
            active: boolean;
            /** Reason */
            reason: string;
        };
        /** EndpointDetail */
        EndpointDetail: {
            endpoint: components["schemas"]["EndpointSummary"];
            sca: components["schemas"]["ScaSummary"];
            source: components["schemas"]["ConnectorState"];
            vulnerabilities: components["schemas"]["VulnerabilitySummary"];
        };
        /** EndpointInventory */
        EndpointInventory: {
            /**
             * By Status
             * @default {}
             */
            by_status: {
                [key: string]: number;
            };
            /** Items */
            items: components["schemas"]["EndpointSummary"][];
            /**
             * Mapped Groups
             * @description Wazuh agent groups mapped to this organization
             */
            mapped_groups: number;
            source: components["schemas"]["ConnectorState"];
        };
        /** EndpointOs */
        EndpointOs: {
            /**
             * Name
             * @default null
             */
            name: string | null;
            /**
             * Platform
             * @default null
             */
            platform: string | null;
            /**
             * Support
             * @default unknown
             * @enum {string}
             */
            support: "supported" | "unsupported" | "unknown";
            /**
             * Version
             * @default null
             */
            version: string | null;
        };
        /** EndpointSummary */
        EndpointSummary: {
            /** Agent Id */
            agent_id: string;
            /**
             * Agent Version
             * @default null
             */
            agent_version: string | null;
            /** Groups */
            groups: string[];
            /**
             * Ip
             * @default null
             */
            ip: string | null;
            /**
             * Last Keepalive At
             * @default null
             */
            last_keepalive_at: string | null;
            /** Name */
            name: string;
            os: components["schemas"]["EndpointOs"];
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "disconnected" | "never_connected" | "pending";
        };
        /** EnrollmentGrant */
        EnrollmentGrant: {
            /**
             * Enrollment Code
             * @description Shown once. Single use. Expires.
             */
            enrollment_code: string;
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /**
             * Grant Id
             * Format: uuid
             */
            grant_id: string;
            /**
             * Site Id
             * Format: uuid
             */
            site_id: string;
        };
        /**
         * EnrollmentGrantCreate
         * @description Operator request (human API, permission service_identities:manage, active org applies).
         */
        EnrollmentGrantCreate: {
            /** Capabilities */
            capabilities: components["schemas"]["Capability"][];
            /**
             * Expires In Minutes
             * @default 60
             */
            expires_in_minutes: number;
            /** Name */
            name: string;
            /**
             * Site Id
             * Format: uuid
             */
            site_id: string;
        };
        /**
         * EnrollmentRequest
         * @description Collector -> API, authenticated by the enrollment code only. No org/site fields: they come from the grant.
         */
        EnrollmentRequest: {
            /** Capabilities */
            capabilities: components["schemas"]["Capability"][];
            /** Collector Version */
            collector_version: string;
            /** Enrollment Code */
            enrollment_code: string;
            /**
             * Host Fingerprint
             * @description Stable host id (e.g. sha256 of machine-id); binds the credential to one host
             */
            host_fingerprint: string;
        };
        /** EnrollmentResponse */
        EnrollmentResponse: {
            /** Config Version */
            config_version: number;
            /** Granted Capabilities */
            granted_capabilities: components["schemas"]["Capability"][];
            /**
             * Identity Id
             * Format: uuid
             */
            identity_id: string;
            /**
             * Machine Credential
             * @description nsk_<id>.<secret>; shown once; store with 0600 permissions
             */
            machine_credential: string;
            /**
             * Site Id
             * Format: uuid
             */
            site_id: string;
        };
        /** ErrorDetail */
        ErrorDetail: {
            /**
             * Code
             * @description Stable machine-readable code, e.g. forbidden, validation_error
             */
            code: string;
            /**
             * Details
             * @default null
             */
            details: unknown | null;
            /** Message */
            message: string;
            /** Request Id */
            request_id: string;
        };
        /** ErrorResponse */
        ErrorResponse: {
            error: components["schemas"]["ErrorDetail"];
        };
        /** EscalationResult */
        EscalationResult: {
            /** Checked */
            checked: number;
            /** Escalated */
            escalated: number;
            /** Notified */
            notified: number;
        };
        /**
         * EvidenceItem
         * @description One piece of evidence the model may cite. Built server-side from the active organisation only.
         */
        EvidenceItem: {
            /**
             * Citation Id
             * @description Evidence key within one bundle
             */
            citation_id: string;
            /** Excerpt */
            excerpt: string;
            /**
             * Observed At
             * @default null
             */
            observed_at: string | null;
            /**
             * Redacted
             * @description True when secrets/PII were removed before inclusion
             * @default false
             */
            redacted: boolean;
            ref: components["schemas"]["ResourceRef"];
        };
        /**
         * ExecutionMode
         * @enum {string}
         */
        ExecutionMode: "dry_run" | "live";
        /** ExecutionOutcome */
        ExecutionOutcome: {
            /** Attempt */
            attempt: number;
            /**
             * Finished At
             * Format: date-time
             */
            finished_at: string;
            /** Message */
            message: string;
            mode: components["schemas"]["ExecutionMode"];
            /**
             * Next Attempt At
             * @default null
             */
            next_attempt_at: string | null;
            /**
             * Ownership Rechecked
             * @description Target re-verified as belonging to the organisation at execution time
             */
            ownership_rechecked: boolean;
            /**
             * Retryable
             * @default false
             */
            retryable: boolean;
            /**
             * Run Id
             * Format: uuid
             */
            run_id: string;
            status: components["schemas"]["OutcomeStatus"];
            /** Step Key */
            step_key: string;
        };
        /**
         * ExecutionReceipt
         * @description The Server 1 bridge's signed answer, verified by the engine before it is stored.
         */
        ExecutionReceipt: {
            /** Adapter */
            adapter: string;
            /**
             * Command
             * @default null
             */
            command: string | null;
            /**
             * Executed At
             * Format: date-time
             */
            executed_at: string;
            /** Reason */
            reason: string;
            /**
             * Replayed
             * @default false
             */
            replayed: boolean;
            /**
             * Request Id
             * Format: uuid
             */
            request_id: string;
            /**
             * Status
             * @enum {string}
             */
            status: "executed" | "dry_run" | "rejected" | "failed";
        };
        /** ExecutiveOverview */
        ExecutiveOverview: {
            /**
             * Assets By Criticality
             * @default {}
             */
            assets_by_criticality: {
                [key: string]: number;
            };
            /**
             * Findings By Severity
             * @default {}
             */
            findings_by_severity: {
                [key: string]: number;
            };
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Incident Trend */
            incident_trend: components["schemas"]["TrendPoint"][];
            /** Kpis */
            kpis: components["schemas"]["Measure"][];
            /** Measures */
            measures: components["schemas"]["Measure"][];
            /** Organization */
            organization: string;
            /** Priorities */
            priorities: components["schemas"]["Priority"][];
            /**
             * Remediation By State
             * @default {}
             */
            remediation_by_state: {
                [key: string]: number;
            };
            score: components["schemas"]["PostureScore"];
            /**
             * Sources
             * @default []
             */
            sources: components["schemas"]["ConnectorState"][];
            /** Vulnerability Trend */
            vulnerability_trend: components["schemas"]["TrendPoint"][];
        };
        /**
         * Exposure
         * @enum {string}
         */
        Exposure: "internal" | "dmz" | "internet" | "unknown";
        /** FeedRun */
        FeedRun: {
            /** Collection */
            collection: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Indicators Imported */
            indicators_imported: number;
            /** Objects Received */
            objects_received: number;
            /** Objects Stored */
            objects_stored: number;
            /**
             * Received At
             * Format: date-time
             */
            received_at: string;
            /** Rejected */
            rejected: number;
            /** Source */
            source: string;
        };
        /** FeedRunList */
        FeedRunList: {
            /** Items */
            items: components["schemas"]["FeedRun"][];
        };
        /** Finding */
        Finding: {
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
            /**
             * Cves
             * @default []
             */
            cves: string[];
            /**
             * Fingerprint
             * @description Stable per asset + check
             */
            fingerprint: string;
            /**
             * First Seen At
             * Format: date-time
             */
            first_seen_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            risk: components["schemas"]["RiskScore"];
            severity: components["schemas"]["Severity"];
            status: components["schemas"]["FindingStatus"];
            /** Title */
            title: string;
        };
        /** FindingCveIntel */
        FindingCveIntel: {
            /**
             * Captured At
             * Format: date-time
             */
            captured_at: string;
            /** Cve Id */
            cve_id: string;
            /**
             * Cvss V3
             * @default null
             */
            cvss_v3: number | null;
            /**
             * Description
             * @default
             */
            description: string;
            /**
             * Epss
             * @default null
             */
            epss: number | null;
            /**
             * Kev
             * @default false
             */
            kev: boolean;
            /** Source */
            source: string;
        };
        /** FindingExplanationRequest */
        FindingExplanationRequest: {
            /**
             * Finding Id
             * Format: uuid
             */
            finding_id: string;
        };
        /**
         * FindingStatus
         * @enum {string}
         */
        FindingStatus: "open" | "acknowledged" | "in_progress" | "fixed_pending_verification" | "verified" | "reopened" | "risk_accepted";
        /** FindingTransition */
        FindingTransition: {
            /**
             * Finding Id
             * Format: uuid
             */
            finding_id: string;
            /** Reason */
            reason: string;
            to_status: components["schemas"]["FindingStatus"];
        };
        /**
         * GatewayKey
         * @description Stored view; never contains the secret.
         */
        GatewayKey: {
            /** Allowed Models */
            allowed_models: string[];
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Created By
             * Format: uuid
             */
            created_by: string;
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /**
             * Key Id
             * Format: uuid
             */
            key_id: string;
            lane: components["schemas"]["Lane"];
            /**
             * Last Used At
             * @default null
             */
            last_used_at: string | null;
            /** Name */
            name: string;
            /**
             * Org Id
             * @description Required for security_analysis keys; null for general keys
             */
            org_id: string | null;
            /** Prefix */
            prefix: string;
            quota: components["schemas"]["Quota"];
            /**
             * Revoked At
             * @default null
             */
            revoked_at: string | null;
        };
        /**
         * GatewayKeyCreate
         * @description Manager action (ai_gateway:manage). The organisation is the ACTIVE organisation for analysis keys.
         */
        GatewayKeyCreate: {
            /** Allowed Models */
            allowed_models: string[];
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /** Name */
            name: string;
            /** Purpose */
            purpose: string;
            quota: components["schemas"]["Quota"];
            /** Scopes */
            scopes: components["schemas"]["KeyScope"][];
        };
        /** GatewayKeyIssued */
        GatewayKeyIssued: {
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /**
             * Key
             * @description Shown ONCE. Only its SHA-256 is stored
             */
            key: string;
            /**
             * Key Id
             * Format: uuid
             */
            key_id: string;
        };
        /** GatewayKeyRevoke */
        GatewayKeyRevoke: {
            /**
             * Key Id
             * Format: uuid
             */
            key_id: string;
            /** Reason */
            reason: string;
        };
        /**
         * GatewayVerdict
         * @description Mail gateway -> API, authenticated by the gateway's service identity (replaces the shared EMAIL_PROXY_TOKEN).
         */
        GatewayVerdict: {
            /** Message Id */
            message_id: string;
            /**
             * Reasons
             * @default []
             */
            reasons: string[];
            /**
             * Received At
             * Format: date-time
             */
            received_at: string;
            /** Recipient Domain */
            recipient_domain: string;
            /**
             * Verdict
             * @enum {string}
             */
            verdict: "deliver" | "quarantine" | "reject";
            /**
             * Verdict Id
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            verdict_id: string;
        };
        /**
         * GeneralInferenceRequest
         * @description Lane `general`. No tenant identifiers or context; the gateway does not enrich it.
         */
        GeneralInferenceRequest: {
            /**
             * Max Tokens
             * @default 512
             */
            max_tokens: number;
            /** Messages */
            messages: components["schemas"]["ChatTurn"][];
            /** Model */
            model: string;
            /**
             * Temperature
             * @default 0.2
             */
            temperature: number;
        };
        /** GeneralInferenceResponse */
        GeneralInferenceResponse: {
            /** Completion Tokens */
            completion_tokens: number;
            /** Latency Ms */
            latency_ms: number;
            /** Model */
            model: string;
            /** Prompt Tokens */
            prompt_tokens: number;
            /** Request Id */
            request_id: string;
            /** Text */
            text: string;
        };
        /** GroupMapping */
        GroupMapping: {
            /**
             * Broad
             * @description A broad group (Wazuh's `default`): shown with a warning
             * @default false
             */
            broad: boolean;
            /**
             * Collection
             * @description A collection group (NOVRSOC_WAZUH_COLLECTION_GROUPS): this mapping is IGNORED for attribution; it never makes the organization an agent's owner
             * @default false
             */
            collection: boolean;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Group Name */
            group_name: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
        };
        /** GroupMappingCreate */
        GroupMappingCreate: {
            /**
             * Acknowledge Broad Group
             * @description Required for a broad group (Wazuh's `default`): every agent belongs to it until it is reassigned, so mapping it attributes every agent that is in no other mapped group to this organization
             * @default false
             */
            acknowledge_broad_group: boolean;
            /** Group Name */
            group_name: string;
        };
        /** GroupMappingList */
        GroupMappingList: {
            /** Items */
            items: components["schemas"]["GroupMapping"][];
        };
        /** HandoverAcknowledge */
        HandoverAcknowledge: {
            /**
             * Note
             * @default
             */
            note: string;
        };
        /** HandoverAlert */
        HandoverAlert: {
            /**
             * Assignee Label
             * @default null
             */
            assignee_label: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            /** Rule Description */
            rule_description: string;
            /** Severity */
            severity: string;
            /** Status */
            status: string;
        };
        /** HandoverApproval */
        HandoverApproval: {
            /** Action */
            action: string;
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Requested By */
            requested_by: string;
            /** Target */
            target: string;
        };
        /** HandoverCase */
        HandoverCase: {
            /**
             * Assignee Label
             * @default null
             */
            assignee_label: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Reference */
            reference: string;
            /** Severity */
            severity: string;
            /** Status */
            status: string;
            /** Title */
            title: string;
        };
        /** HandoverCreate */
        HandoverCreate: {
            /**
             * Incoming User Id
             * @default null
             */
            incoming_user_id: string | null;
            /**
             * Shift End
             * Format: date-time
             */
            shift_end: string;
            /**
             * Shift Start
             * Format: date-time
             */
            shift_start: string;
            /** Summary */
            summary: string;
            /**
             * Watch Items
             * @default []
             */
            watch_items: string[];
        };
        /** HandoverDraft */
        HandoverDraft: {
            /** Recipients */
            recipients: components["schemas"]["UserRef"][];
            snapshot: components["schemas"]["HandoverSnapshot"];
        };
        /** HandoverList */
        HandoverList: {
            /** Items */
            items: components["schemas"]["HandoverView"][];
        };
        /** HandoverSnapshot */
        HandoverSnapshot: {
            /**
             * Cases
             * @default []
             */
            cases: components["schemas"]["HandoverCase"][];
            /**
             * My Assignments
             * @default 0
             */
            my_assignments: number;
            /** Open Cases */
            open_cases: number;
            /**
             * Pending Approvals
             * @default []
             */
            pending_approvals: components["schemas"]["HandoverApproval"][];
            /**
             * Sla At Risk
             * @default []
             */
            sla_at_risk: components["schemas"]["CaseSlaView"][];
            /**
             * Sla Breached
             * @default 0
             */
            sla_breached: number;
            /**
             * Taken At
             * Format: date-time
             */
            taken_at: string;
            /**
             * Top Alerts
             * @default []
             */
            top_alerts: components["schemas"]["HandoverAlert"][];
            /** Unassigned Critical Alerts */
            unassigned_critical_alerts: number;
            /** Unresolved Alerts */
            unresolved_alerts: number;
        };
        /** HandoverView */
        HandoverView: {
            /**
             * Acknowledged At
             * @default null
             */
            acknowledged_at: string | null;
            /** @default null */
            acknowledged_by: components["schemas"]["ActorRef"] | null;
            /**
             * Acknowledgement Note
             * @default
             */
            acknowledgement_note: string;
            author: components["schemas"]["ActorRef"];
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Incoming Label
             * @default null
             */
            incoming_label: string | null;
            /**
             * Incoming User Id
             * @default null
             */
            incoming_user_id: string | null;
            /**
             * Shift End
             * Format: date-time
             */
            shift_end: string;
            /**
             * Shift Start
             * Format: date-time
             */
            shift_start: string;
            snapshot: components["schemas"]["HandoverSnapshot"];
            /**
             * Status
             * @enum {string}
             */
            status: "submitted" | "acknowledged";
            /** Summary */
            summary: string;
            /** Watch Items */
            watch_items: string[];
        };
        /** HealthResponse */
        HealthResponse: {
            /** Service */
            service: string;
            /**
             * Status
             * @constant
             */
            status: "ok";
            /** Version */
            version: string;
        };
        /**
         * HealthState
         * @enum {string}
         */
        HealthState: "ok" | "degraded" | "failing" | "unconfigured";
        /** HeartbeatAck */
        HeartbeatAck: {
            /** Latest Config Version */
            latest_config_version: number;
            /**
             * Revoked
             * @default false
             * @constant
             */
            revoked: false;
            /**
             * Rotate Credential By
             * @default null
             */
            rotate_credential_by: string | null;
            /**
             * Server Time
             * Format: date-time
             */
            server_time: string;
        };
        /** HumanReview */
        HumanReview: {
            /**
             * Decision
             * @enum {string}
             */
            decision: "accept" | "accept_with_edits" | "reject";
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * Reviewed At
             * Format: date-time
             */
            reviewed_at: string;
            reviewer: components["schemas"]["ActorRef"];
        };
        /** Indicator */
        Indicator: {
            /** Confidence */
            confidence: number;
            /**
             * First Seen At
             * Format: date-time
             */
            first_seen_at: string;
            /** Source */
            source: string;
            tlp: components["schemas"]["Tlp"];
            type: components["schemas"]["IndicatorType"];
            /** Value */
            value: string;
        };
        /** IndicatorContext */
        IndicatorContext: {
            indicator: components["schemas"]["IndicatorRecord"];
            /** Related */
            related: components["schemas"]["RelatedObject"][];
        };
        /**
         * IndicatorImport
         * @description Either plain indicators or a STIX 2.1 bundle (only `indicator` objects with a single-comparison pattern on a
         *     supported observable are accepted; anything else is reported as skipped, never guessed).
         */
        IndicatorImport: {
            /**
             * Indicators
             * @default []
             */
            indicators: components["schemas"]["Indicator"][];
            /** Source */
            source: string;
            /**
             * Stix Bundle
             * @default null
             */
            stix_bundle: {
                [key: string]: unknown;
            } | null;
            /** @default amber */
            tlp: components["schemas"]["Tlp"];
        };
        /** IndicatorImportResult */
        IndicatorImportResult: {
            /** Imported */
            imported: number;
            /**
             * Skipped
             * @default []
             */
            skipped: string[];
            /** Unchanged */
            unchanged: number;
        };
        /** IndicatorList */
        IndicatorList: {
            /** Items */
            items: components["schemas"]["IndicatorRecord"][];
        };
        /** IndicatorProvenance */
        IndicatorProvenance: {
            /**
             * Imported At
             * Format: date-time
             */
            imported_at: string;
            /**
             * Imported By
             * @default
             */
            imported_by: string;
            /** Source */
            source: string;
            /**
             * Source Ref
             * @description The source's own id (e.g. a STIX id or feed record)
             * @default
             */
            source_ref: string;
        };
        /** IndicatorRecord */
        IndicatorRecord: {
            /** Confidence */
            confidence: number;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            provenance: components["schemas"]["IndicatorProvenance"];
            /** Stix Id */
            stix_id: string;
            tlp: components["schemas"]["Tlp"];
            type: components["schemas"]["IndicatorType"];
            /**
             * Valid From
             * Format: date-time
             */
            valid_from: string;
            /**
             * Valid Until
             * @default null
             */
            valid_until: string | null;
            /**
             * Value
             * @description Normalized value used for matching
             */
            value: string;
        };
        /**
         * IndicatorType
         * @enum {string}
         */
        IndicatorType: "ipv4" | "ipv6" | "domain" | "url" | "sha256" | "cve";
        /** InsightFeedback */
        InsightFeedback: {
            /**
             * Match Id
             * Format: uuid
             */
            match_id: string;
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * Verdict
             * @enum {string}
             */
            verdict: "true_positive" | "false_positive" | "benign";
        };
        /**
         * InsightMatch
         * @description An indicator matched against THIS organisation's evidence.
         */
        InsightMatch: {
            /**
             * Id
             * Format: uuid
             */
            id: string;
            indicator: components["schemas"]["Indicator"];
            matched: components["schemas"]["ResourceRef"];
            /**
             * Matched At
             * Format: date-time
             */
            matched_at: string;
            severity: components["schemas"]["Severity"];
            /**
             * Verdict
             * @default unreviewed
             * @enum {string}
             */
            verdict: "unreviewed" | "true_positive" | "false_positive" | "benign";
        };
        /** InsightMatchList */
        InsightMatchList: {
            /** Items */
            items: components["schemas"]["InsightMatchView"][];
        };
        /** InsightMatchView */
        InsightMatchView: {
            /**
             * Alert Id
             * Format: uuid
             */
            alert_id: string;
            confidence: components["schemas"]["MatchConfidence"];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            indicator: components["schemas"]["IndicatorRecord"];
            /**
             * Matched At
             * Format: date-time
             */
            matched_at: string;
            observable: components["schemas"]["Observable"];
            /**
             * Verdict
             * @enum {string}
             */
            verdict: "unreviewed" | "true_positive" | "false_positive" | "benign";
        };
        /** InvestigationAssistRequest */
        InvestigationAssistRequest: {
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /** Question */
            question: string;
        };
        /**
         * JobRun
         * @description One unit of scheduled or queued work. Unique (job_type, idempotency_key): a repeat is a no-op.
         */
        JobRun: {
            /**
             * Attempt
             * @default 1
             */
            attempt: number;
            /**
             * Failure
             * @default null
             */
            failure: ("retryable" | "permanent") | null;
            /**
             * Failure Reason
             * @default
             */
            failure_reason: string;
            /**
             * Finished At
             * @default null
             */
            finished_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Idempotency Key
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            idempotency_key: string;
            /** Job Type */
            job_type: string;
            /**
             * Max Attempts
             * @default 3
             */
            max_attempts: number;
            /**
             * Next Attempt At
             * @default null
             */
            next_attempt_at: string | null;
            /**
             * Org Id
             * @description Set for tenant work; null only for platform-wide jobs
             */
            org_id: string | null;
            /**
             * Queued At
             * Format: date-time
             */
            queued_at: string;
            /**
             * Started At
             * @default null
             */
            started_at: string | null;
            state: components["schemas"]["JobState"];
        };
        /**
         * JobState
         * @enum {string}
         */
        JobState: "queued" | "running" | "succeeded" | "failed" | "cancelled";
        /**
         * KeyScope
         * @enum {string}
         */
        KeyScope: "inference:general" | "analysis:security";
        /**
         * Lane
         * @enum {string}
         */
        Lane: "general" | "security_analysis";
        /** LanePolicy */
        LanePolicy: {
            /** Allowed Models */
            allowed_models: string[];
            lane: components["schemas"]["Lane"];
            /**
             * Max Concurrency
             * @description Shared by every caller of the lane
             */
            max_concurrency: number;
            /** Max Input Chars */
            max_input_chars: number;
            /** Max Output Tokens */
            max_output_tokens: number;
            /** Timeout Seconds */
            timeout_seconds: number;
        };
        /** LogSourceCreate */
        LogSourceCreate: {
            /**
             * Authorization Reference
             * @description The client authorization (ticket, contract clause) for collecting this device's logs
             */
            authorization_reference: string;
            /**
             * Device Type
             * @enum {string}
             */
            device_type: "firewall" | "router" | "switch" | "linux_server" | "windows_server" | "network_appliance" | "storage" | "other";
            /**
             * Enabled
             * @default true
             */
            enabled: boolean;
            /**
             * Host
             * @description agentless: the host as configured on the Wazuh manager
             * @default
             */
            host: string;
            /**
             * Kind
             * @default syslog
             * @enum {string}
             */
            kind: "syslog" | "agentless";
            /** Name */
            name: string;
            /**
             * Network
             * @description CIDR the source sits in
             * @default null
             */
            network: string | null;
            /**
             * Notes
             * @default
             */
            notes: string;
            /**
             * Port
             * @default null
             */
            port: number | null;
            /**
             * Protocol
             * @default udp
             * @enum {string}
             */
            protocol: "udp" | "tcp" | "tls" | "ssh";
            /**
             * Site Id
             * @default null
             */
            site_id: string | null;
            /**
             * Source Ip
             * @description syslog: the sender address
             * @default null
             */
            source_ip: string | null;
            /**
             * Vendor
             * @default
             */
            vendor: string;
        };
        /** LogSourceList */
        LogSourceList: {
            /** Items */
            items: components["schemas"]["LogSourceView"][];
        };
        /** LogSourceReassign */
        LogSourceReassign: {
            /**
             * Org Id
             * Format: uuid
             * @description The organization that now owns the device
             */
            org_id: string;
            /** Reason */
            reason: string;
        };
        /** LogSourceRetire */
        LogSourceRetire: {
            /** Reason */
            reason: string;
        };
        /**
         * LogSourceUpdate
         * @description A field left out (null) is unchanged. Changing source_ip or host changes what the source matches.
         */
        LogSourceUpdate: {
            /**
             * Authorization Reference
             * @default null
             */
            authorization_reference: string | null;
            /**
             * Clear Network
             * @default false
             */
            clear_network: boolean;
            /**
             * Clear Site
             * @default false
             */
            clear_site: boolean;
            /**
             * Device Type
             * @default null
             */
            device_type: ("firewall" | "router" | "switch" | "linux_server" | "windows_server" | "network_appliance" | "storage" | "other") | null;
            /**
             * Enabled
             * @default null
             */
            enabled: boolean | null;
            /**
             * Host
             * @default null
             */
            host: string | null;
            /**
             * Name
             * @default null
             */
            name: string | null;
            /**
             * Network
             * @default null
             */
            network: string | null;
            /**
             * Notes
             * @default null
             */
            notes: string | null;
            /**
             * Port
             * @default null
             */
            port: number | null;
            /**
             * Protocol
             * @default null
             */
            protocol: ("udp" | "tcp" | "tls" | "ssh") | null;
            /**
             * Site Id
             * @default null
             */
            site_id: string | null;
            /**
             * Source Ip
             * @default null
             */
            source_ip: string | null;
            /**
             * Vendor
             * @default null
             */
            vendor: string | null;
        };
        /** LogSourceView */
        LogSourceView: {
            /** Asset Id */
            asset_id: string | null;
            /** Authorization Reference */
            authorization_reference: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Device Type
             * @enum {string}
             */
            device_type: "firewall" | "router" | "switch" | "linux_server" | "windows_server" | "network_appliance" | "storage" | "other";
            /** Enabled */
            enabled: boolean;
            /** Event Count */
            event_count: number;
            /** Host */
            host: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "syslog" | "agentless";
            /** Last Event At */
            last_event_at: string | null;
            /** Match Value */
            match_value: string;
            /** Name */
            name: string;
            /** Network */
            network: string | null;
            /** Notes */
            notes: string;
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /** Port */
            port: number | null;
            /**
             * Protocol
             * @enum {string}
             */
            protocol: "udp" | "tcp" | "tls" | "ssh";
            /**
             * Retired At
             * @default null
             */
            retired_at: string | null;
            /**
             * Retired Reason
             * @default
             */
            retired_reason: string;
            /** Site Id */
            site_id: string | null;
            /**
             * Site Name
             * @default null
             */
            site_name: string | null;
            /** Source Ip */
            source_ip: string | null;
            /**
             * Status
             * @description receiving: an event in the last hour; quiet: in the last 24 hours; silent: none for 24 hours or more; never_received; disabled; retired (reassigned or removed, kept for history)
             * @enum {string}
             */
            status: "receiving" | "quiet" | "silent" | "never_received" | "disabled" | "retired";
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
            /** Vendor */
            vendor: string;
        };
        /** LoginRequest */
        LoginRequest: {
            /** Email */
            email: string;
            /** Password */
            password: string;
        };
        /** LoginResponse */
        LoginResponse: {
            /**
             * Csrf Token
             * @description Send back as X-CSRF-Token on POST/PUT/PATCH/DELETE (also set as a cookie)
             */
            csrf_token: string;
            session: components["schemas"]["SessionInfo"];
        };
        /**
         * MatchConfidence
         * @description How the match confidence was computed (deterministic policy, explained).
         */
        MatchConfidence: {
            /**
             * Band
             * @enum {string}
             */
            band: "low" | "medium" | "high";
            /** Reasons */
            reasons: string[];
            /** Score */
            score: number;
        };
        /** MatchRunResult */
        MatchRunResult: {
            /** Alerts Scanned */
            alerts_scanned: number;
            /** New Matches */
            new_matches: number;
            /** Observables */
            observables: number;
        };
        /** Measure */
        Measure: {
            /**
             * Denominator
             * @default null
             */
            denominator: number | null;
            /**
             * Evidence Href
             * @default
             */
            evidence_href: string;
            /**
             * Formula
             * @default
             */
            formula: string;
            /**
             * Higher Is Better
             * @default true
             */
            higher_is_better: boolean;
            /** Key */
            key: string;
            /** Label */
            label: string;
            /**
             * Numerator
             * @default null
             */
            numerator: number | null;
            /**
             * Reason
             * @default
             */
            reason: string;
            /**
             * State
             * @enum {string}
             */
            state: "ok" | "unavailable" | "not_permitted";
            /**
             * Unit
             * @enum {string}
             */
            unit: "percent" | "count" | "minutes" | "score";
            /**
             * Value
             * @default null
             */
            value: number | null;
            /**
             * Weight
             * @default 0
             */
            weight: number;
        };
        /**
         * MembershipGrant
         * @description Give an existing user of the active organization access to another organization (assignment).
         */
        MembershipGrant: {
            /**
             * Access Scope
             * @enum {string}
             */
            access_scope: "operations" | "reporting";
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
        };
        /** MembershipList */
        MembershipList: {
            /** Items */
            items: components["schemas"]["MembershipView"][];
            /**
             * User Id
             * Format: uuid
             */
            user_id: string;
        };
        /** MembershipSummary */
        MembershipSummary: {
            /**
             * Access Scope
             * @enum {string}
             */
            access_scope: "home" | "operations" | "reporting";
            org: components["schemas"]["OrgSummary"];
            /**
             * Role
             * @enum {string}
             */
            role: "super_admin" | "soc_manager" | "analyst" | "executive" | "portal_user";
        };
        /** MembershipView */
        MembershipView: {
            /** Access Scope */
            access_scope: string;
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /** Org Name */
            org_name: string;
            /** Role */
            role: string;
        };
        /**
         * ModelOutput
         * @description The JSON shape the model is asked to produce (validated before anything is stored or shown).
         */
        ModelOutput: {
            /**
             * Confidence
             * @enum {string}
             */
            confidence: "low" | "medium" | "high";
            /**
             * Limitations
             * @default []
             */
            limitations: string[];
            /**
             * Missing Evidence
             * @default []
             */
            missing_evidence: string[];
            /**
             * Recommendations
             * @default []
             */
            recommendations: components["schemas"]["Recommendation"][];
            /** @default null */
            severity_assessment: components["schemas"]["SeverityAssessment"] | null;
            /**
             * Statements
             * @default []
             */
            statements: components["schemas"]["Statement"][];
            /** Summary */
            summary: string;
        };
        /** ModelRef */
        ModelRef: {
            /**
             * Digest
             * @default null
             */
            digest: string | null;
            /** Name */
            name: string;
            /**
             * Provider
             * @default ollama_local
             * @constant
             */
            provider: "ollama_local";
        };
        /**
         * ModuleState
         * @description Phase 4: what a product module can do right now, as the API knows it.
         */
        ModuleState: {
            /** Key */
            key: string;
            /** Label */
            label: string;
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * State
             * @enum {string}
             */
            state: "live" | "not_available" | "restricted";
        };
        /** MonitoringRun */
        MonitoringRun: {
            /**
             * Finished At
             * @default null
             */
            finished_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * New Findings
             * @default 0
             */
            new_findings: number;
            /**
             * Outcome
             * @default null
             */
            outcome: ("completed" | "source_unconfigured" | "rate_limited" | "failed") | null;
            /**
             * Started At
             * Format: date-time
             */
            started_at: string;
            /**
             * Subject Id
             * Format: uuid
             */
            subject_id: string;
        };
        /** MonitoringRunList */
        MonitoringRunList: {
            /** Items */
            items: components["schemas"]["MonitoringRun"][];
        };
        /**
         * NhaiJob
         * @description One asynchronous NHAI request. Inference runs in a separate worker; the API only queues and reads jobs.
         *     `result` is present only when `status` is `succeeded`; `error_code` explains every other final state.
         */
        NhaiJob: {
            /** Attempts */
            attempts: number;
            /**
             * Deadline At
             * Format: date-time
             */
            deadline_at: string;
            /**
             * Error Code
             * @default null
             */
            error_code: string | null;
            /**
             * Finished At
             * @default null
             */
            finished_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Queued At
             * Format: date-time
             */
            queued_at: string;
            requested_by: components["schemas"]["ActorRef"];
            /** @default null */
            result: components["schemas"]["NhaiResult"] | null;
            /**
             * Started At
             * @default null
             */
            started_at: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "queued" | "running" | "succeeded" | "failed" | "timed_out";
            subject: components["schemas"]["ResourceRef"];
            task: components["schemas"]["NhaiTask"];
        };
        /** NhaiJobList */
        NhaiJobList: {
            /** Items */
            items: components["schemas"]["NhaiJob"][];
        };
        /** NhaiResult */
        NhaiResult: {
            /** Citations */
            citations: components["schemas"]["Citation"][];
            /**
             * Confidence
             * @enum {string}
             */
            confidence: "low" | "medium" | "high";
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Latency Ms */
            latency_ms: number;
            /**
             * Limitations
             * @default []
             */
            limitations: string[];
            /**
             * Missing Evidence
             * @description Phase 5: evidence that would change the assessment and is not in the bundle. Always includes the gaps found by the deterministic checker, whatever the model said
             * @default []
             */
            missing_evidence: string[];
            model: components["schemas"]["ModelRef"];
            /**
             * Recommendations
             * @default []
             */
            recommendations: components["schemas"]["Recommendation"][];
            /** @default null */
            review: components["schemas"]["HumanReview"] | null;
            /** @default null */
            severity_assessment: components["schemas"]["SeverityAssessment"] | null;
            /**
             * Statements
             * @default []
             */
            statements: components["schemas"]["Statement"][];
            /**
             * Status
             * @default draft
             * @enum {string}
             */
            status: "draft" | "accepted" | "rejected" | "superseded";
            subject: components["schemas"]["ResourceRef"];
            /** Summary */
            summary: string;
            task: components["schemas"]["NhaiTask"];
            /**
             * Unsupported Statements Dropped
             * @default 0
             */
            unsupported_statements_dropped: number;
            /**
             * Validation Notes
             * @description Phase 5: every deterministic adjustment made to the model output (confidence cap, dropped statements, severity disagreement), so a reviewer sees exactly what was changed and why
             * @default []
             */
            validation_notes: string[];
        };
        /**
         * NhaiReviewRequest
         * @description A human decision on a succeeded job's draft (nhai:review). The reviewer is the signed-in user.
         */
        NhaiReviewRequest: {
            /**
             * Decision
             * @enum {string}
             */
            decision: "accept" | "accept_with_edits" | "reject";
            /**
             * Note
             * @default
             */
            note: string;
        };
        /**
         * NhaiTask
         * @enum {string}
         */
        NhaiTask: "alert_explanation" | "behavioural_insight_summary" | "investigation_assistance" | "case_note_draft" | "finding_explanation" | "asset_summary" | "chat_answer";
        /** NotificationList */
        NotificationList: {
            /** Items */
            items: components["schemas"]["NotificationView"][];
            /** Unread */
            unread: number;
        };
        /** NotificationView */
        NotificationView: {
            /** Body */
            body: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Kind */
            kind: string;
            /** Link */
            link: string;
            /**
             * Read At
             * @default null
             */
            read_at: string | null;
            /** Title */
            title: string;
        };
        /**
         * Observable
         * @description A normalized value extracted deterministically from one stored alert.
         */
        Observable: {
            /** Source Field */
            source_field: string;
            type: components["schemas"]["IndicatorType"];
            /** Value */
            value: string;
        };
        /** Observation */
        Observation: {
            /**
             * Check Id
             * @description Scanner check id, e.g. Greenbone NVT OID
             * @default null
             */
            check_id: string | null;
            /**
             * Cves
             * @default []
             */
            cves: string[];
            /**
             * Cvss V3
             * @default null
             */
            cvss_v3: number | null;
            /**
             * Evidence Ref
             * @default null
             */
            evidence_ref: string | null;
            kind: components["schemas"]["ObservationKind"];
            /**
             * Port
             * @default null
             */
            port: number | null;
            /**
             * Protocol
             * @default null
             */
            protocol: ("tcp" | "udp") | null;
            /** @default null */
            severity: components["schemas"]["Severity"] | null;
            target: components["schemas"]["ScopeEntry"];
            /**
             * Title
             * @default null
             */
            title: string | null;
        };
        /**
         * ObservationKind
         * @enum {string}
         */
        ObservationKind: "host" | "service" | "technology" | "finding";
        /** OnboardingStatus */
        OnboardingStatus: {
            /**
             * Completed
             * @default 0
             */
            completed: number;
            /**
             * Next Step
             * @default null
             */
            next_step: string | null;
            /**
             * Optional Steps
             * @description Steps that do not count towards completion (not every organization has syslog or agentless sources)
             * @default []
             */
            optional_steps: string[];
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /** Org Slug */
            org_slug: string;
            /** Steps */
            steps: {
                [key: string]: boolean;
            };
            /**
             * Total
             * @default 0
             */
            total: number;
        };
        /** OrgAnalyticsRow */
        OrgAnalyticsRow: {
            /** Alerts 7D */
            alerts_7d: number;
            /** Assets */
            assets: number;
            /** Critical Findings */
            critical_findings: number;
            /** Kind */
            kind: string;
            /**
             * Last Alert At
             * @default null
             */
            last_alert_at: string | null;
            /** Open Alerts */
            open_alerts: number;
            /** Open Cases */
            open_cases: number;
            /** Open Findings */
            open_findings: number;
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /** Org Name */
            org_name: string;
            /**
             * Plan Code
             * @default null
             */
            plan_code: string | null;
            /** Status */
            status: string;
            /**
             * Subscription Status
             * @default null
             */
            subscription_status: string | null;
            /** Users */
            users: number;
        };
        /** OrgBillingRow */
        OrgBillingRow: {
            /** Assets */
            assets: number;
            /**
             * Max Assets
             * @default null
             */
            max_assets: number | null;
            /**
             * Max Users
             * @default null
             */
            max_users: number | null;
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /** Org Name */
            org_name: string;
            /**
             * Over Limit
             * @default []
             */
            over_limit: string[];
            /**
             * Plan Code
             * @default null
             */
            plan_code: string | null;
            /**
             * Plan Name
             * @default null
             */
            plan_name: string | null;
            /**
             * Renews At
             * @default null
             */
            renews_at: string | null;
            /**
             * Status
             * @default null
             */
            status: string | null;
            /** Users */
            users: number;
        };
        /** OrgDetail */
        OrgDetail: {
            /** Alerts 7D */
            alerts_7d: number;
            /**
             * Archived At
             * @default null
             */
            archived_at: string | null;
            /** Assets */
            assets: number;
            /**
             * Contact Email
             * @default
             */
            contact_email: string;
            /**
             * Contact Name
             * @default
             */
            contact_name: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            integrations: components["schemas"]["OrgIntegrations"];
            /**
             * Kind
             * @enum {string}
             */
            kind: "platform" | "client";
            /** Name */
            name: string;
            /**
             * Next Step
             * @default null
             */
            next_step: string | null;
            /**
             * Notes
             * @default
             */
            notes: string;
            onboarding: components["schemas"]["OnboardingStatus"];
            /** Onboarding Completed */
            onboarding_completed: number;
            /** Onboarding Total */
            onboarding_total: number;
            /** Open Cases */
            open_cases: number;
            /** Sites */
            sites: number;
            /** Slug */
            slug: string;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "suspended" | "archived";
            /**
             * Status Reason
             * @default
             */
            status_reason: string;
            /**
             * Timezone
             * @default UTC
             */
            timezone: string;
            /**
             * Updated At
             * @default null
             */
            updated_at: string | null;
            /** Users */
            users: number;
        };
        /** OrgDirectory */
        OrgDirectory: {
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Items */
            items: components["schemas"]["OrgDirectoryRow"][];
            /** Total */
            total: number;
        };
        /** OrgDirectoryRow */
        OrgDirectoryRow: {
            /** Alerts 7D */
            alerts_7d: number;
            /** Assets */
            assets: number;
            /**
             * Contact Email
             * @default
             */
            contact_email: string;
            /**
             * Contact Name
             * @default
             */
            contact_name: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            integrations: components["schemas"]["OrgIntegrations"];
            /**
             * Kind
             * @enum {string}
             */
            kind: "platform" | "client";
            /** Name */
            name: string;
            /**
             * Next Step
             * @default null
             */
            next_step: string | null;
            /** Onboarding Completed */
            onboarding_completed: number;
            /** Onboarding Total */
            onboarding_total: number;
            /** Open Cases */
            open_cases: number;
            /** Sites */
            sites: number;
            /** Slug */
            slug: string;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "suspended" | "archived";
            /**
             * Status Reason
             * @default
             */
            status_reason: string;
            /**
             * Timezone
             * @default UTC
             */
            timezone: string;
            /**
             * Updated At
             * @default null
             */
            updated_at: string | null;
            /** Users */
            users: number;
        };
        /** OrgIntegrations */
        OrgIntegrations: {
            /**
             * Health
             * @enum {string}
             */
            health: "ok" | "attention" | "not_configured" | "inactive";
            /**
             * Last Alert At
             * @default null
             */
            last_alert_at: string | null;
            /** Log Sources */
            log_sources: number;
            /** Log Sources Disabled */
            log_sources_disabled: number;
            /**
             * Log Sources Never
             * @description Enabled sources that have not sent any event yet
             */
            log_sources_never: number;
            /**
             * Log Sources Receiving
             * @description Enabled sources with an event in the last hour
             */
            log_sources_receiving: number;
            /**
             * Notes
             * @description Why the health is what it is, one line per finding
             * @default []
             */
            notes: string[];
            /** Service Identities */
            service_identities: number;
            /**
             * Wazuh Agents
             * @description Wazuh agents reconciled into the organization's asset inventory
             */
            wazuh_agents: number;
            /** Wazuh Groups */
            wazuh_groups: number;
        };
        /** OrgList */
        OrgList: {
            /**
             * All Organizations
             * @description True for super_admin: the list is every active organisation
             */
            all_organizations: boolean;
            /** Items */
            items: components["schemas"]["OrgSummary"][];
        };
        /**
         * OrgPosture
         * @description One organization's security posture, computed from its own records at request time.
         */
        OrgPosture: {
            /**
             * Alerts 24H
             * @default 0
             */
            alerts_24h: number;
            /**
             * Assets
             * @default 0
             */
            assets: number;
            /**
             * Critical Alerts 24H
             * @default 0
             */
            critical_alerts_24h: number;
            /**
             * Critical Cases
             * @default 0
             */
            critical_cases: number;
            /**
             * Critical Findings
             * @default 0
             */
            critical_findings: number;
            /**
             * High Alerts 24H
             * @default 0
             */
            high_alerts_24h: number;
            /**
             * Intel Matches 7D
             * @default 0
             */
            intel_matches_7d: number;
            /**
             * Last Alert At
             * @default null
             */
            last_alert_at: string | null;
            /**
             * Nhai Awaiting Review
             * @default 0
             */
            nhai_awaiting_review: number;
            /**
             * Nhai Failed 24H
             * @default 0
             */
            nhai_failed_24h: number;
            /**
             * Nhai Queued
             * @default 0
             */
            nhai_queued: number;
            /**
             * Open Alerts
             * @default 0
             */
            open_alerts: number;
            /**
             * Open Cases
             * @default 0
             */
            open_cases: number;
            /**
             * Open Findings
             * @default 0
             */
            open_findings: number;
            org: components["schemas"]["CommandOrg"];
            /**
             * Overdue Remediation
             * @default 0
             */
            overdue_remediation: number;
            /**
             * Posture
             * @enum {string}
             */
            posture: "critical" | "elevated" | "normal" | "no_data";
            /**
             * Posture Reasons
             * @default []
             */
            posture_reasons: string[];
            /**
             * Reports 7D
             * @default 0
             */
            reports_7d: number;
            /**
             * Scan Policy Enabled
             * @default false
             */
            scan_policy_enabled: boolean;
            /**
             * Scans Failed 7D
             * @default 0
             */
            scans_failed_7d: number;
            /**
             * Scans Running
             * @default 0
             */
            scans_running: number;
            /**
             * Soar Pending Approvals
             * @default 0
             */
            soar_pending_approvals: number;
            /**
             * Soar Runs 7D
             * @default 0
             */
            soar_runs_7d: number;
        };
        /**
         * OrgStatusChange
         * @description suspended: members cannot sign in or switch to it; telemetry keeps arriving. archived: kept for the record; it
         *     must hold no Wazuh group mapping and no live log source first, so no event can reach it.
         */
        OrgStatusChange: {
            /** Reason */
            reason: string;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "suspended" | "archived";
        };
        /** OrgSummary */
        OrgSummary: {
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Name */
            name: string;
            /** Slug */
            slug: string;
        };
        /**
         * OrgUpdate
         * @description Profile fields; a field left out (null) is unchanged. The slug never changes (it identifies the organization).
         */
        OrgUpdate: {
            /**
             * Contact Email
             * @default null
             */
            contact_email: string | null;
            /**
             * Contact Name
             * @default null
             */
            contact_name: string | null;
            /**
             * Name
             * @default null
             */
            name: string | null;
            /**
             * Notes
             * @default null
             */
            notes: string | null;
            /**
             * Timezone
             * @default null
             */
            timezone: string | null;
        };
        /**
         * OutcomeStatus
         * @enum {string}
         */
        OutcomeStatus: "succeeded" | "skipped_not_configured" | "failed" | "cancelled" | "dry_run";
        /**
         * PasswordChangeRequest
         * @description POST /api/v1/auth/password. The new password must differ from the current one; other sessions are revoked.
         */
        PasswordChangeRequest: {
            /** Current Password */
            current_password: string;
            /** New Password */
            new_password: string;
        };
        /** PhishingCandidate */
        PhishingCandidate: {
            /** Domain */
            domain: string;
            /**
             * First Seen At
             * Format: date-time
             */
            first_seen_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Resembles */
            resembles: string;
            risk: components["schemas"]["Severity"];
            /** Similarity */
            similarity: number;
            /**
             * Status
             * @enum {string}
             */
            status: "new" | "investigating" | "confirmed" | "dismissed" | "takedown_requested";
        };
        /** PlatformAnalytics */
        PlatformAnalytics: {
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Organizations */
            organizations: components["schemas"]["OrgAnalyticsRow"][];
            /** Totals */
            totals: {
                [key: string]: number;
            };
        };
        /** PlatformBackupState */
        PlatformBackupState: {
            /**
             * Last Drill At
             * @default null
             */
            last_drill_at: string | null;
            /**
             * Last Drill Status
             * @default null
             */
            last_drill_status: string | null;
            /**
             * Last Succeeded At
             * @default null
             */
            last_succeeded_at: string | null;
            /** Note */
            note: string;
            /**
             * Visible
             * @description False when the caller may not read platform backup history
             */
            visible: boolean;
        };
        /** PlatformHealth */
        PlatformHealth: {
            /** Components */
            components: components["schemas"]["ComponentHealth"][];
            /** Failures 24H */
            failures_24h: {
                [key: string]: unknown;
            }[];
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Queues */
            queues: {
                [key: string]: unknown;
            };
            /** Workers */
            workers: {
                [key: string]: unknown;
            }[];
        };
        /**
         * PlatformStatus
         * @description Phase 4 dashboard readiness. Connector states come from configuration and real checks only.
         */
        PlatformStatus: {
            /** Connectors */
            connectors: components["schemas"]["ConnectorState"][];
            /**
             * Database
             * @enum {string}
             */
            database: "ok" | "unavailable";
            /** Migration */
            migration: string;
            /** Modules */
            modules: components["schemas"]["ModuleState"][];
        };
        /** PlaybookCreate */
        PlaybookCreate: {
            /**
             * Description
             * @default
             */
            description: string;
            /**
             * @default {
             *       "max_runs_per_day": 20,
             *       "min_case_severity": "low",
             *       "modes": [
             *         "dry_run"
             *       ]
             *     }
             */
            execution_policy: components["schemas"]["PlaybookExecutionPolicy"];
            /** Name */
            name: string;
            /** Steps */
            steps: components["schemas"]["PlaybookStep"][];
            /** Title */
            title: string;
            /**
             * @default {
             *       "min_level": 0,
             *       "mitre": [],
             *       "rule_ids": []
             *     }
             */
            triggers: components["schemas"]["PlaybookTriggers"];
        };
        /**
         * PlaybookExecutionPolicy
         * @description Consolidation: how an APPROVED playbook version may run. Live mode still needs the organization's response
         *     policy (live_enabled) and a human approval for every consequential step; this policy can only narrow that.
         */
        PlaybookExecutionPolicy: {
            /**
             * Max Runs Per Day
             * @default 20
             */
            max_runs_per_day: number;
            /**
             * Min Case Severity
             * @default low
             * @enum {string}
             */
            min_case_severity: "low" | "medium" | "high" | "critical";
            /**
             * Modes
             * @default [
             *       "dry_run"
             *     ]
             */
            modes: components["schemas"]["ExecutionMode"][];
        };
        /**
         * PlaybookExecutionRequest
         * @description Requested by an analyst/manager for a case. Creates a run in state pending (or awaiting_approval).
         */
        PlaybookExecutionRequest: {
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /**
             * Idempotency Key
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            idempotency_key: string;
            /** @default dry_run */
            mode: components["schemas"]["ExecutionMode"];
            /**
             * Playbook Id
             * Format: uuid
             */
            playbook_id: string;
            /** Playbook Version */
            playbook_version: number;
        };
        /** PlaybookList */
        PlaybookList: {
            /** Items */
            items: components["schemas"]["PlaybookView"][];
        };
        /** PlaybookRecommendation */
        PlaybookRecommendation: {
            /** Matched On */
            matched_on: string[];
            playbook: components["schemas"]["PlaybookView"];
            /**
             * Proposed Targets
             * @default {}
             */
            proposed_targets: {
                [key: string]: string;
            };
        };
        /**
         * PlaybookReview
         * @description Approve or reject a version that is pending approval. The author can never approve their own version.
         */
        PlaybookReview: {
            /**
             * Decision
             * @enum {string}
             */
            decision: "approve" | "reject";
            /** Note */
            note: string;
        };
        /** PlaybookStep */
        PlaybookStep: {
            action: components["schemas"]["ActionType"];
            /**
             * Max Attempts
             * @default 3
             */
            max_attempts: number;
            /**
             * Parameters
             * @default {}
             */
            parameters: {
                [key: string]: string | number | boolean | string[];
            };
            /** Step Key */
            step_key: string;
            /**
             * Timeout Seconds
             * @default 120
             */
            timeout_seconds: number;
        };
        /**
         * PlaybookTriggers
         * @description Deterministic recommendation criteria matched against a case's alerts (never auto-executed).
         */
        PlaybookTriggers: {
            /**
             * Min Level
             * @default 0
             */
            min_level: number;
            /**
             * Mitre
             * @default []
             */
            mitre: string[];
            /**
             * Rule Ids
             * @default []
             */
            rule_ids: string[];
        };
        /** PlaybookValidation */
        PlaybookValidation: {
            /**
             * Checked At
             * Format: date-time
             */
            checked_at: string;
            /**
             * Errors
             * @default []
             */
            errors: string[];
            /** Valid */
            valid: boolean;
            /**
             * Warnings
             * @default []
             */
            warnings: string[];
        };
        /** PlaybookVersionList */
        PlaybookVersionList: {
            /** Items */
            items: components["schemas"]["PlaybookView"][];
            /** Name */
            name: string;
        };
        /** PlaybookView */
        PlaybookView: {
            /**
             * Approved At
             * @default null
             */
            approved_at: string | null;
            /** @default null */
            approved_by: components["schemas"]["ActorRef"] | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Created By Label
             * @default
             */
            created_by_label: string;
            /**
             * Description
             * @default
             */
            description: string;
            /** Enabled */
            enabled: boolean;
            /**
             * @default {
             *       "max_runs_per_day": 20,
             *       "min_case_severity": "low",
             *       "modes": [
             *         "dry_run"
             *       ]
             *     }
             */
            execution_policy: components["schemas"]["PlaybookExecutionPolicy"];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Name */
            name: string;
            /**
             * Review Note
             * @default
             */
            review_note: string;
            /**
             * Status
             * @description Consolidation: only an approved, enabled version can run
             * @default draft
             * @enum {string}
             */
            status: "draft" | "validated" | "pending_approval" | "approved" | "retired";
            /** Steps */
            steps: components["schemas"]["PlaybookStep"][];
            /** Title */
            title: string;
            triggers: components["schemas"]["PlaybookTriggers"];
            /** @default null */
            validation: components["schemas"]["PlaybookValidation"] | null;
            /** Version */
            version: number;
        };
        /**
         * PolicyWindow
         * @description A weekly window in the policy's timezone during which scans of the organization may run.
         */
        PolicyWindow: {
            /** End Minute */
            end_minute: number;
            /** Start Minute */
            start_minute: number;
            /**
             * Weekday
             * @description 0 = Monday
             */
            weekday: number;
        };
        /** PostureAssessment */
        PostureAssessment: {
            /** Areas */
            areas: components["schemas"]["ControlArea"][];
            compliance: components["schemas"]["ComplianceView"];
            /** Gaps */
            gaps: components["schemas"]["PostureGap"][];
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Remediation Trend */
            remediation_trend: components["schemas"]["TrendPoint"][];
            score: components["schemas"]["PostureScore"];
        };
        /** PostureGap */
        PostureGap: {
            /** Detail */
            detail: string;
            /** Href */
            href: string;
            /** Key */
            key: string;
            /**
             * Severity
             * @enum {string}
             */
            severity: "critical" | "high" | "medium" | "low";
            /** Title */
            title: string;
        };
        /** PostureScore */
        PostureScore: {
            /**
             * Contributing
             * @default []
             */
            contributing: string[];
            /** Coverage Percent */
            coverage_percent: number;
            /**
             * Excluded
             * @default []
             */
            excluded: string[];
            /** Method */
            method: string;
            /**
             * Score
             * @default null
             */
            score: number | null;
            /**
             * State
             * @enum {string}
             */
            state: "ok" | "insufficient_data";
        };
        /** Priority */
        Priority: {
            /** Detail */
            detail: string;
            /** Href */
            href: string;
            /** Kind */
            kind: string;
            /**
             * Severity
             * @enum {string}
             */
            severity: "critical" | "high" | "medium" | "low";
            /** Title */
            title: string;
        };
        /** QuarantineSummary */
        QuarantineSummary: {
            /** By Reason */
            by_reason: {
                [key: string]: number;
            };
            /** Last 24H */
            last_24h: number;
            /**
             * Unattributed Sources
             * @default []
             */
            unattributed_sources: components["schemas"]["QuarantinedSource"][];
            /** Unmapped Groups */
            unmapped_groups: string[];
        };
        /**
         * QuarantinedSource
         * @description Events of the Wazuh manager (agent 000) that no live registration could attribute.
         */
        QuarantinedSource: {
            /** Events */
            events: number;
            /**
             * Kind
             * @enum {string}
             */
            kind: "syslog" | "agentless" | "manager_local";
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            /** Reason */
            reason: string;
            /**
             * Value
             * @description The sender IP (syslog), the agentless host, or the manager's local log location
             */
            value: string;
        };
        /** Quota */
        Quota: {
            /** Max Concurrency */
            max_concurrency: number;
            /** Requests Per Minute */
            requests_per_minute: number;
            /** Tokens Per Day */
            tokens_per_day: number;
        };
        /** QuotaStatus */
        QuotaStatus: {
            /**
             * Key Id
             * Format: uuid
             */
            key_id: string;
            quota: components["schemas"]["Quota"];
            /** Requests This Minute */
            requests_this_minute: number;
            /** Tokens Today */
            tokens_today: number;
        };
        /** ReadinessCheck */
        ReadinessCheck: {
            /**
             * Detail
             * @default
             */
            detail: string;
            /** Name */
            name: string;
            /** Ok */
            ok: boolean;
        };
        /** ReadinessResponse */
        ReadinessResponse: {
            /** Checks */
            checks: components["schemas"]["ReadinessCheck"][];
            /**
             * Status
             * @enum {string}
             */
            status: "ready" | "not_ready";
        };
        /** Recommendation */
        Recommendation: {
            /** @default null */
            action: components["schemas"]["ActionType"] | null;
            /** Citation Ids */
            citation_ids: string[];
            /**
             * Executes Automatically
             * @default false
             * @constant
             */
            executes_automatically: false;
            /** Requires Human Approval */
            requires_human_approval: boolean;
            /** Text */
            text: string;
        };
        /** RecommendationList */
        RecommendationList: {
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /** Items */
            items: components["schemas"]["PlaybookRecommendation"][];
        };
        /**
         * RecoveryDecision
         * @description assess / approve / reject / not_recoverable, by someone other than the requester (recovery:manage).
         */
        RecoveryDecision: {
            /**
             * Backup Reference
             * @default
             */
            backup_reference: string;
            /**
             * Decision
             * @enum {string}
             */
            decision: "assess" | "approve" | "reject" | "not_recoverable";
            /** Reason */
            reason: string;
        };
        /** RecoveryEventView */
        RecoveryEventView: {
            /** Actor Label */
            actor_label: string;
            /** Body */
            body: string;
            /**
             * Details
             * @default {}
             */
            details: {
                [key: string]: unknown;
            };
            /** Id */
            id: number;
            /**
             * Kind
             * @enum {string}
             */
            kind: "submitted" | "status_changed" | "note" | "evidence" | "verification";
            /**
             * Occurred At
             * Format: date-time
             */
            occurred_at: string;
        };
        /** RecoveryPlanCreate */
        RecoveryPlanCreate: {
            /**
             * Backup Source
             * @enum {string}
             */
            backup_source: "novrsoc_platform_backup" | "external_provider" | "manual_procedure";
            /** Name */
            name: string;
            /**
             * Owning Unit
             * @default
             */
            owning_unit: string;
            /**
             * Procedure
             * @default
             */
            procedure: string;
            /**
             * Provider Name
             * @default
             */
            provider_name: string;
            /**
             * Rpo Minutes
             * @default null
             */
            rpo_minutes: number | null;
            /**
             * Rto Minutes
             * @default null
             */
            rto_minutes: number | null;
            /** Scope */
            scope: string;
        };
        /** RecoveryPlanList */
        RecoveryPlanList: {
            /** Items */
            items: components["schemas"]["RecoveryPlanView"][];
        };
        /** RecoveryPlanTested */
        RecoveryPlanTested: {
            /** Note */
            note: string;
            /**
             * Tested At
             * Format: date-time
             */
            tested_at: string;
        };
        /** RecoveryPlanView */
        RecoveryPlanView: {
            /**
             * Backup Source
             * @enum {string}
             */
            backup_source: "novrsoc_platform_backup" | "external_provider" | "manual_procedure";
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Execution
             * @description What NovrSOC can actually do for this plan
             */
            execution: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Last Tested At
             * @default null
             */
            last_tested_at: string | null;
            /** Name */
            name: string;
            /**
             * Owning Unit
             * @default
             */
            owning_unit: string;
            /**
             * Procedure
             * @default
             */
            procedure: string;
            /**
             * Provider Name
             * @default
             */
            provider_name: string;
            /**
             * Rpo Minutes
             * @default null
             */
            rpo_minutes: number | null;
            /**
             * Rto Minutes
             * @default null
             */
            rto_minutes: number | null;
            /** Scope */
            scope: string;
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** RecoveryProgress */
        RecoveryProgress: {
            /**
             * Evidence
             * @default []
             */
            evidence: string[];
            /** Note */
            note: string;
            /**
             * Recovered Point
             * @default null
             */
            recovered_point: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "in_progress" | "completed";
        };
        /** RecoveryRequestCreate */
        RecoveryRequestCreate: {
            /** Affected Data */
            affected_data: string;
            /** Description */
            description: string;
            /**
             * Loss Detected At
             * Format: date-time
             */
            loss_detected_at: string;
            /**
             * Plan Id
             * @default null
             */
            plan_id: string | null;
            /**
             * Requested Recovery Point
             * @default null
             */
            requested_recovery_point: string | null;
            /** Title */
            title: string;
        };
        /** RecoveryRequestList */
        RecoveryRequestList: {
            /** Items */
            items: components["schemas"]["RecoveryRequestView"][];
        };
        /** RecoveryRequestView */
        RecoveryRequestView: {
            /**
             * Achieved Rpo Minutes
             * @default null
             */
            achieved_rpo_minutes: number | null;
            /**
             * Achieved Rto Minutes
             * @default null
             */
            achieved_rto_minutes: number | null;
            /** Affected Data */
            affected_data: string;
            /**
             * Backup Reference
             * @default
             */
            backup_reference: string;
            /**
             * Backup Source
             * @default null
             */
            backup_source: ("novrsoc_platform_backup" | "external_provider" | "manual_procedure") | null;
            /**
             * Completed At
             * @default null
             */
            completed_at: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** @default null */
            decided_by: components["schemas"]["ActorRef"] | null;
            /**
             * Decision Reason
             * @default null
             */
            decision_reason: string | null;
            /** Description */
            description: string;
            /**
             * Events
             * @default []
             */
            events: components["schemas"]["RecoveryEventView"][];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Loss Detected At
             * Format: date-time
             */
            loss_detected_at: string;
            /**
             * Plan Id
             * @default null
             */
            plan_id: string | null;
            /**
             * Plan Name
             * @default null
             */
            plan_name: string | null;
            /**
             * Recovered Point
             * @default null
             */
            recovered_point: string | null;
            requested_by: components["schemas"]["ActorRef"];
            /**
             * Requested Recovery Point
             * @default null
             */
            requested_recovery_point: string | null;
            /**
             * Rpo Target Minutes
             * @default null
             */
            rpo_target_minutes: number | null;
            /**
             * Rto Target Minutes
             * @default null
             */
            rto_target_minutes: number | null;
            /**
             * Started At
             * @default null
             */
            started_at: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "submitted" | "assessing" | "approved" | "in_progress" | "completed" | "rejected" | "not_recoverable";
            /** Title */
            title: string;
            /**
             * Verification
             * @enum {string}
             */
            verification: "pending" | "verified" | "failed" | "not_applicable";
        };
        /** RecoveryVerification */
        RecoveryVerification: {
            /** Note */
            note: string;
            /**
             * Result
             * @enum {string}
             */
            result: "verified" | "failed" | "not_applicable";
        };
        /**
         * RejectReason
         * @enum {string}
         */
        RejectReason: "key_invalid" | "key_revoked_or_expired" | "wrong_lane" | "model_not_allowed" | "rate_limited" | "daily_quota_exhausted" | "concurrency_limit" | "input_too_large" | "timeout" | "backend_unavailable";
        /** RelatedObject */
        RelatedObject: {
            /**
             * Edge
             * @enum {string}
             */
            edge: "outgoing" | "incoming";
            /** Name */
            name: string;
            /** Relationship Type */
            relationship_type: string;
            /** Stix Id */
            stix_id: string;
            /** Type */
            type: string;
        };
        /** RemediationTask */
        RemediationTask: {
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
            /**
             * Due At
             * @default null
             */
            due_at: string | null;
            /** Finding Ids */
            finding_ids: string[];
            /**
             * Fixed Version
             * @description From patch intelligence (OSV) when known
             * @default null
             */
            fixed_version: string | null;
            /**
             * Guidance
             * @default
             */
            guidance: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Owner Id
             * @default null
             */
            owner_id: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "open" | "in_progress" | "done" | "cancelled";
        };
        /** RemediationTaskList */
        RemediationTaskList: {
            /**
             * By Status
             * @default {}
             */
            by_status: {
                [key: string]: number;
            };
            /** Items */
            items: components["schemas"]["RemediationTaskView"][];
            /**
             * Overdue
             * @default 0
             */
            overdue: number;
        };
        /** RemediationTaskUpdate */
        RemediationTaskUpdate: {
            /**
             * Assignee Id
             * @default null
             */
            assignee_id: string | null;
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * Status
             * @default null
             */
            status: ("open" | "in_progress") | null;
        };
        /** RemediationTaskView */
        RemediationTaskView: {
            /**
             * Asset Id
             * @default null
             */
            asset_id: string | null;
            /**
             * Assignee Id
             * @default null
             */
            assignee_id: string | null;
            /**
             * Assignee Label
             * @default null
             */
            assignee_label: string | null;
            /**
             * Due At
             * Format: date-time
             */
            due_at: string;
            /**
             * Finding Id
             * Format: uuid
             */
            finding_id: string;
            /** Finding Status */
            finding_status: string;
            /** Finding Title */
            finding_title: string;
            /** Host */
            host: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Note */
            note: string;
            /** Overdue */
            overdue: boolean;
            /** Priority */
            priority: string;
            severity: components["schemas"]["Severity"];
            /**
             * Status
             * @enum {string}
             */
            status: "open" | "in_progress" | "done" | "cancelled";
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** ReportArtifact */
        ReportArtifact: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Data States
             * @description Honest state of each section's data source, shown in the report
             * @default {}
             */
            data_states: {
                [key: string]: "ok" | "empty" | "integration_unconfigured" | "error" | "local_fixture" | "not_permitted";
            };
            /**
             * Format
             * @enum {string}
             */
            format: "pdf" | "csv" | "json";
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Period End
             * Format: date-time
             */
            period_end: string;
            /**
             * Period Start
             * Format: date-time
             */
            period_start: string;
            /**
             * Sha256
             * @default null
             */
            sha256: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "queued" | "generating" | "ready" | "failed";
            type: components["schemas"]["ReportType"];
        };
        /**
         * ReportDetail
         * @description Phase 4: a generated report with its sections. Unavailable sources are listed as such, never as zero.
         */
        ReportDetail: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Data States
             * @description Honest state of each section's data source, shown in the report
             * @default {}
             */
            data_states: {
                [key: string]: "ok" | "empty" | "integration_unconfigured" | "error" | "local_fixture" | "not_permitted";
            };
            /**
             * Failure Reason
             * @default
             */
            failure_reason: string;
            /**
             * Format
             * @enum {string}
             */
            format: "pdf" | "csv" | "json";
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Period End
             * Format: date-time
             */
            period_end: string;
            /**
             * Period Start
             * Format: date-time
             */
            period_start: string;
            /**
             * Sections
             * @default []
             */
            sections: components["schemas"]["ReportSection"][];
            /**
             * Sha256
             * @default null
             */
            sha256: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "queued" | "generating" | "ready" | "failed";
            type: components["schemas"]["ReportType"];
        };
        /**
         * ReportList
         * @description Phase 4: the organization's report history (newest first).
         */
        ReportList: {
            /** Items */
            items: components["schemas"]["ReportArtifact"][];
        };
        /** ReportRequest */
        ReportRequest: {
            /**
             * Format
             * @default pdf
             * @enum {string}
             */
            format: "pdf" | "csv" | "json";
            /**
             * Idempotency Key
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            idempotency_key: string;
            /**
             * Period End
             * Format: date-time
             */
            period_end: string;
            /**
             * Period Start
             * Format: date-time
             */
            period_start: string;
            type: components["schemas"]["ReportType"];
        };
        /** ReportSchedule */
        ReportSchedule: {
            /**
             * Active
             * @default true
             */
            active: boolean;
            /** Cron */
            cron: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Recipient User Ids */
            recipient_user_ids: string[];
            /**
             * Timezone
             * @default Africa/Lagos
             */
            timezone: string;
            type: components["schemas"]["ReportType"];
        };
        /** ReportSection */
        ReportSection: {
            /**
             * Data
             * @description Section figures; empty whenever state is not ok/local_fixture
             * @default {}
             */
            data: {
                [key: string]: unknown;
            };
            /** Key */
            key: string;
            /**
             * Note
             * @default
             */
            note: string;
            /**
             * State
             * @enum {string}
             */
            state: "ok" | "empty" | "integration_unconfigured" | "error" | "local_fixture" | "not_permitted";
            /** Title */
            title: string;
        };
        /**
         * ReportType
         * @enum {string}
         */
        ReportType: "vms_executive" | "vms_technical" | "soc_monthly" | "compliance_sca" | "email_security" | "cnii_sector" | "organization_summary" | "executive" | "secops" | "threat_intel" | "brand_protection" | "sla" | "audit";
        /** ResourceRef */
        ResourceRef: {
            /** Id */
            id: string;
            /** Type */
            type: string;
        };
        /** RestoreDrillRequest */
        RestoreDrillRequest: {
            /**
             * Backup Job Id
             * Format: uuid
             */
            backup_job_id: string;
            /**
             * Idempotency Key
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            idempotency_key: string;
            /**
             * Target
             * @description The only allowed target; restoring over live data is out of contract
             * @default disposable_instance
             * @constant
             */
            target: "disposable_instance";
        };
        /** RestoreDrillResult */
        RestoreDrillResult: {
            /**
             * Backup Job Id
             * Format: uuid
             */
            backup_job_id: string;
            /** Duration Seconds */
            duration_seconds: number;
            /**
             * Finished At
             * Format: date-time
             */
            finished_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Restored Tables */
            restored_tables: number;
            /** Row Count Checks Passed */
            row_count_checks_passed: boolean;
            /**
             * Status
             * @enum {string}
             */
            status: "succeeded" | "failed";
        };
        /** RetestRequest */
        RetestRequest: {
            /**
             * Note
             * @default
             */
            note: string;
        };
        /** RetryPolicy */
        RetryPolicy: {
            /**
             * Initial Backoff Seconds
             * @default 5
             */
            initial_backoff_seconds: number;
            /**
             * Max Attempts
             * @default 3
             */
            max_attempts: number;
            /**
             * Max Backoff Seconds
             * @default 300
             */
            max_backoff_seconds: number;
            /**
             * Retry On
             * @default [
             *       "timeout",
             *       "connector_unavailable"
             *     ]
             */
            retry_on: ("timeout" | "connector_unavailable" | "rate_limited")[];
        };
        /** RiskAssetRow */
        RiskAssetRow: {
            /**
             * Asset Id
             * @default null
             */
            asset_id: string | null;
            /**
             * Criticality
             * @default null
             */
            criticality: string | null;
            /**
             * Exposure
             * @default null
             */
            exposure: string | null;
            /** Kev */
            kev: number;
            /** Max Risk */
            max_risk: number;
            /** Name */
            name: string;
            /** Open Findings */
            open_findings: number;
            /** P1 */
            p1: number;
        };
        /**
         * RiskScore
         * @description Contextual 0-100 (legacy lib/riskScore.ts inputs). The formula version is part of the result.
         */
        RiskScore: {
            /** @default medium */
            criticality: components["schemas"]["Criticality"];
            /**
             * Cvss
             * @default null
             */
            cvss: number | null;
            /**
             * Epss
             * @default null
             */
            epss: number | null;
            /** @default unknown */
            exposure: components["schemas"]["Exposure"];
            /** Formula Version */
            formula_version: string;
            /**
             * Kev
             * @default false
             */
            kev: boolean;
            /** Score */
            score: number;
        };
        /**
         * RunCreate
         * @description PlaybookExecutionRequest plus the human justification recorded on any approval it creates.
         */
        RunCreate: {
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /**
             * Idempotency Key
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            idempotency_key: string;
            /** Justification */
            justification: string;
            /** @default dry_run */
            mode: components["schemas"]["ExecutionMode"];
            /**
             * Playbook Id
             * Format: uuid
             */
            playbook_id: string;
            /** Playbook Version */
            playbook_version: number;
        };
        /** RunList */
        RunList: {
            /** Items */
            items: components["schemas"]["RunView"][];
        };
        /**
         * RunState
         * @enum {string}
         */
        RunState: "pending" | "awaiting_approval" | "running" | "succeeded" | "failed" | "cancelled";
        /** RunView */
        RunView: {
            /**
             * Case Id
             * Format: uuid
             */
            case_id: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            mode: components["schemas"]["ExecutionMode"];
            /**
             * Playbook Id
             * Format: uuid
             */
            playbook_id: string;
            /** Playbook Name */
            playbook_name: string;
            /** Playbook Version */
            playbook_version: number;
            requested_by: components["schemas"]["ActorRef"];
            state: components["schemas"]["RunState"];
            /**
             * Steps
             * @default []
             */
            steps: components["schemas"]["StepView"][];
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** ScaCheckResult */
        ScaCheckResult: {
            /** Check Id */
            check_id: number;
            /**
             * Compliance
             * @description Framework -> control ids, e.g. {'cis': ['1.1.1'], 'pci_dss': ['2.2']}
             * @default {}
             */
            compliance: {
                [key: string]: string[];
            };
            /**
             * Rationale
             * @default
             */
            rationale: string;
            /**
             * Remediation
             * @default
             */
            remediation: string;
            result: components["schemas"]["ScaResult"];
            /** Title */
            title: string;
        };
        /**
         * ScaPolicyResult
         * @description One SCA policy evaluation for one endpoint (Wazuh /sca/{agent_id} + /sca/{agent_id}/checks/{policy}).
         */
        ScaPolicyResult: {
            /** Agent Id */
            agent_id: string;
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
            /**
             * Checks
             * @default []
             */
            checks: components["schemas"]["ScaCheckResult"][];
            /** Failed */
            failed: number;
            /** Not Applicable */
            not_applicable: number;
            /** Passed */
            passed: number;
            /** Policy Id */
            policy_id: string;
            /** Policy Name */
            policy_name: string;
            /**
             * Scanned At
             * Format: date-time
             */
            scanned_at: string;
            /** Score Percent */
            score_percent: number;
        };
        /** ScaPolicySummaryView */
        ScaPolicySummaryView: {
            /** Failed */
            failed: number;
            /** Name */
            name: string;
            /** Not Applicable */
            not_applicable: number;
            /** Passed */
            passed: number;
            /** Policy Id */
            policy_id: string;
            /**
             * Scanned At
             * Format: date-time
             */
            scanned_at: string;
            /** Score Percent */
            score_percent: number;
        };
        /**
         * ScaResult
         * @enum {string}
         */
        ScaResult: "passed" | "failed" | "not_applicable";
        /** ScaSummary */
        ScaSummary: {
            /**
             * Policies
             * @default []
             */
            policies: components["schemas"]["ScaPolicySummaryView"][];
            source: components["schemas"]["ConnectorState"];
        };
        /**
         * ScanActivity
         * @enum {string}
         */
        ScanActivity: "discovery" | "ports" | "vuln_nuclei" | "vuln_openvas";
        /**
         * ScanClaimResult
         * @description Answer to a worker's claim. `job` is present only when a job is handed out. In this release scanning is
         *     disabled by design, so the API answers `scanning_disabled` and never hands out a job.
         */
        ScanClaimResult: {
            /** @default null */
            job: components["schemas"]["ScanJobClaim"] | null;
            /**
             * Reason
             * @enum {string}
             */
            reason: "job" | "no_job" | "scanning_disabled" | "policy_disabled" | "outside_scan_window" | "concurrency_limit";
        };
        /**
         * ScanConnectivityAssignment
         * @description Tells a collector with SCAN_RELAY which APPROVED scan jobs it may relay. Derived from VMS scope approvals.
         */
        ScanConnectivityAssignment: {
            /**
             * Allowed Ports
             * @default []
             */
            allowed_ports: number[];
            /**
             * Assignment Id
             * Format: uuid
             */
            assignment_id: string;
            /**
             * Scan Job Id
             * Format: uuid
             */
            scan_job_id: string;
            /**
             * Scope Approval Id
             * Format: uuid
             */
            scope_approval_id: string;
            /** Targets */
            targets: components["schemas"]["SiteScopedAddress"][];
            /**
             * Window End
             * Format: date-time
             */
            window_end: string;
            /**
             * Window Start
             * Format: date-time
             */
            window_start: string;
        };
        /**
         * ScanJobClaim
         * @description Sent to the VMS worker on claim (atomic, FOR UPDATE SKIP LOCKED). Greenbone config names are worker-side.
         */
        ScanJobClaim: {
            activity: components["schemas"]["ScanActivity"];
            /**
             * Deadline At
             * Format: date-time
             */
            deadline_at: string;
            /**
             * Job Id
             * Format: uuid
             */
            job_id: string;
            /**
             * Max Rate Pps
             * @description The organization's scan-policy packet-rate ceiling; the worker never exceeds it (nor its own)
             * @default null
             */
            max_rate_pps: number | null;
            /** Max Runtime Seconds */
            max_runtime_seconds: number;
            /**
             * Protected Networks
             * @description Never touched, whatever the targets say (scan policy)
             * @default []
             */
            protected_networks: string[];
            /** Targets */
            targets: components["schemas"]["ScopeEntry"][];
        };
        /**
         * ScanJobRequest
         * @description Human API (vms:scan). Refused unless every target is inside an active ScopeApproval allowing the activity.
         */
        ScanJobRequest: {
            activity: components["schemas"]["ScanActivity"];
            /**
             * Idempotency Key
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            idempotency_key: string;
            /**
             * Profile
             * @default standard
             * @enum {string}
             */
            profile: "discovery" | "standard" | "full";
            /**
             * Scope Approval Id
             * Format: uuid
             */
            scope_approval_id: string;
            /** Targets */
            targets: components["schemas"]["ScopeEntry"][];
        };
        /**
         * ScanResultBatch
         * @description Worker -> API. No org field: the job (and so the organisation) comes from job_id + worker identity.
         */
        ScanResultBatch: {
            /**
             * Batch Id
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            batch_id: string;
            /**
             * Job Id
             * Format: uuid
             */
            job_id: string;
            /** Observations */
            observations: components["schemas"]["Observation"][];
            /**
             * Per Target Outcome
             * @default {}
             */
            per_target_outcome: {
                [key: string]: "completed" | "unreachable" | "refused_out_of_scope" | "failed" | "no_route";
            };
        };
        /** ScanWindow */
        ScanWindow: {
            /** End Minute */
            end_minute: number;
            /** Start Minute */
            start_minute: number;
            /**
             * Timezone
             * @default Africa/Lagos
             */
            timezone: string;
            /** Weekday */
            weekday: number;
        };
        /**
         * ScopeApproval
         * @description An organisation-approved scope (P27 model). OpenVAS is allowed only when listed here; never by env var.
         */
        ScopeApproval: {
            /** Allowed Activities */
            allowed_activities: components["schemas"]["ScanActivity"][];
            /**
             * Approved At
             * Format: date-time
             */
            approved_at: string;
            /**
             * Approved By
             * Format: uuid
             */
            approved_by: string;
            /** Authorization Reference */
            authorization_reference: string;
            /** Entries */
            entries: components["schemas"]["ScopeEntry"][];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Revoked At
             * @default null
             */
            revoked_at: string | null;
            /**
             * Scan Windows
             * @default []
             */
            scan_windows: components["schemas"]["ScanWindow"][];
            /**
             * Valid Until
             * Format: date-time
             */
            valid_until: string;
        };
        /** ScopeEntry */
        ScopeEntry: {
            /**
             * Kind
             * @enum {string}
             */
            kind: "domain" | "ip" | "cidr" | "url";
            /**
             * Site Id
             * @description Required for private addresses and ranges
             * @default null
             */
            site_id: string | null;
            /** Value */
            value: string;
        };
        /** ServiceIdentityCreate */
        ServiceIdentityCreate: {
            /**
             * Kind
             * @enum {string}
             */
            kind: "collector" | "vms_worker" | "forwarder" | "email_gateway" | "backup_agent" | "ti_feeder";
            /** Name */
            name: string;
            /**
             * Scopes
             * @default []
             */
            scopes: string[];
            /**
             * Site Id
             * @default null
             */
            site_id: string | null;
        };
        /**
         * ServiceIdentityIssued
         * @description The credential (nsk_...) is shown ONCE, here; only its SHA-256 is stored.
         */
        ServiceIdentityIssued: {
            /** Credential */
            credential: string;
            identity: components["schemas"]["ServiceIdentityView"];
        };
        /** ServiceIdentityList */
        ServiceIdentityList: {
            /** Items */
            items: components["schemas"]["ServiceIdentityView"][];
        };
        /** ServiceIdentityView */
        ServiceIdentityView: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "collector" | "vms_worker" | "forwarder" | "email_gateway" | "backup_agent" | "ti_feeder";
            /**
             * Last Used At
             * @default null
             */
            last_used_at: string | null;
            /** Name */
            name: string;
            /**
             * Revoked At
             * @default null
             */
            revoked_at: string | null;
            /** Scopes */
            scopes: string[];
            /**
             * Site Id
             * @default null
             */
            site_id: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "revoked";
        };
        /** ServiceList */
        ServiceList: {
            /**
             * By Product
             * @default {}
             */
            by_product: {
                [key: string]: number;
            };
            /** Items */
            items: components["schemas"]["ServiceRow"][];
        };
        /** ServiceRow */
        ServiceRow: {
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
            /** Asset Name */
            asset_name: string;
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            /** Name */
            name: string;
            /** Port */
            port: number;
            /** Product */
            product: string;
            /** Protocol */
            protocol: string;
            /** Source */
            source: string;
            /** Version */
            version: string;
        };
        /**
         * ServiceWhoAmI
         * @description GET /api/v1/service/whoami. Everything here comes from the identity record, nothing from the request.
         */
        ServiceWhoAmI: {
            /**
             * Identity Id
             * Format: uuid
             */
            identity_id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "collector" | "vms_worker" | "forwarder" | "email_gateway" | "backup_agent" | "ti_feeder";
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /** Scopes */
            scopes: string[];
            /** Site Id */
            site_id: string | null;
        };
        /**
         * SessionInfo
         * @description GET /api/v1/auth/me. Permissions are those of the home role, applied to the active organisation.
         */
        SessionInfo: {
            active_org: components["schemas"]["OrgSummary"];
            /** Cross Org */
            cross_org: boolean;
            home_org: components["schemas"]["OrgSummary"];
            /** Memberships */
            memberships: components["schemas"]["MembershipSummary"][];
            /**
             * Password Change Required
             * @description The account still has a temporary password: every route except /auth/me, /auth/password and /auth/logout answers 403 password_change_required until it is changed
             * @default false
             */
            password_change_required: boolean;
            /** Permissions */
            permissions: string[];
            /**
             * Role
             * @enum {string}
             */
            role: "super_admin" | "soc_manager" | "analyst" | "executive" | "portal_user";
            user: components["schemas"]["UserSummary"];
        };
        /**
         * Severity
         * @enum {string}
         */
        Severity: "info" | "low" | "medium" | "high" | "critical";
        /**
         * SeverityAssessment
         * @description Phase 5 (additive): the model's evidence-grounded view of an alert's severity. Advisory only: it never
         *     changes a stored severity; an analyst decides.
         */
        SeverityAssessment: {
            /**
             * Agrees With Stored
             * @default null
             */
            agrees_with_stored: boolean | null;
            /** Citation Ids */
            citation_ids: string[];
            /**
             * Proposed
             * @enum {string}
             */
            proposed: "critical" | "high" | "medium" | "low";
            /** Rationale */
            rationale: string;
            /**
             * Uncertainty
             * @enum {string}
             */
            uncertainty: "low" | "medium" | "high";
        };
        /** Site */
        Site: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Description */
            description: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Name */
            name: string;
            /** Network Cidrs */
            network_cidrs: string[];
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
        };
        /** SiteCreate */
        SiteCreate: {
            /**
             * Description
             * @default
             */
            description: string;
            /** Name */
            name: string;
            /**
             * Network Cidrs
             * @default []
             */
            network_cidrs: string[];
        };
        /** SiteList */
        SiteList: {
            /** Items */
            items: components["schemas"]["Site"][];
        };
        /**
         * SiteScopedAddress
         * @description An IP address is only meaningful inside a site: 10.0.0.5 at site A is not 10.0.0.5 at site B.
         */
        SiteScopedAddress: {
            /**
             * Hostname
             * @default null
             */
            hostname: string | null;
            /** Ip */
            ip: string;
            /**
             * Site Id
             * Format: uuid
             */
            site_id: string;
        };
        /** SlaPerformance */
        SlaPerformance: {
            /** Days */
            days: number;
            /**
             * Note
             * @default
             */
            note: string;
            /** Rows */
            rows: components["schemas"]["SlaPerformanceRow"][];
            /** Weekly */
            weekly: components["schemas"]["SlaWeek"][];
        };
        /** SlaPerformanceRow */
        SlaPerformanceRow: {
            /** Cases */
            cases: number;
            /**
             * Median Resolution Minutes
             * @default null
             */
            median_resolution_minutes: number | null;
            /**
             * Median Response Minutes
             * @default null
             */
            median_response_minutes: number | null;
            /** Resolution Breached */
            resolution_breached: number;
            /** Resolution Met */
            resolution_met: number;
            /** Response Breached */
            response_breached: number;
            /** Response Met */
            response_met: number;
            /**
             * Severity
             * @enum {string}
             */
            severity: "critical" | "high" | "medium" | "low";
            /** Without Policy */
            without_policy: number;
        };
        /** SlaPolicyInput */
        SlaPolicyInput: {
            /**
             * Escalate Before Minutes
             * @default 0
             */
            escalate_before_minutes: number;
            /**
             * Escalate To Role
             * @default soc_manager
             * @enum {string}
             */
            escalate_to_role: "soc_manager" | "super_admin";
            /** Resolution Minutes */
            resolution_minutes: number;
            /** Response Minutes */
            response_minutes: number;
            /**
             * Severity
             * @enum {string}
             */
            severity: "critical" | "high" | "medium" | "low";
        };
        /** SlaPolicyList */
        SlaPolicyList: {
            /** Items */
            items: components["schemas"]["SlaPolicyView"][];
        };
        /** SlaPolicySet */
        SlaPolicySet: {
            /** Policies */
            policies: components["schemas"]["SlaPolicyInput"][];
        };
        /** SlaPolicyView */
        SlaPolicyView: {
            /**
             * Escalate Before Minutes
             * @default 0
             */
            escalate_before_minutes: number;
            /**
             * Escalate To Role
             * @default soc_manager
             * @enum {string}
             */
            escalate_to_role: "soc_manager" | "super_admin";
            /** Resolution Minutes */
            resolution_minutes: number;
            /** Response Minutes */
            response_minutes: number;
            /**
             * Severity
             * @enum {string}
             */
            severity: "critical" | "high" | "medium" | "low";
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** SlaStatus */
        SlaStatus: {
            /**
             * Counts
             * @default {}
             */
            counts: {
                [key: string]: number;
            };
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Items */
            items: components["schemas"]["CaseSlaView"][];
            /** Policies Configured */
            policies_configured: number;
        };
        /** SlaWeek */
        SlaWeek: {
            /** Breached */
            breached: number;
            /** Met */
            met: number;
            /**
             * Week Start
             * Format: date
             */
            week_start: string;
        };
        /** SnapshotCreate */
        SnapshotCreate: {
            /**
             * Kind
             * @enum {string}
             */
            kind: "cvss" | "ioc";
            /**
             * Reason
             * @default
             */
            reason: string;
            /**
             * Subject
             * @description A CVE id, or an indicator id
             */
            subject: string;
        };
        /** SnapshotList */
        SnapshotList: {
            /** Items */
            items: components["schemas"]["SnapshotView"][];
        };
        /** SnapshotView */
        SnapshotView: {
            /**
             * Captured At
             * Format: date-time
             */
            captured_at: string;
            /** Captured Label */
            captured_label: string;
            /** Content */
            content: {
                [key: string]: unknown;
            };
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kind
             * @enum {string}
             */
            kind: "cvss" | "ioc";
            /** Reason */
            reason: string;
            /** Sha256 */
            sha256: string;
            /** Subject */
            subject: string;
        };
        /**
         * SoarAuditEvent
         * @description Every state change of a run, approval or step is also an audit_events row with these actions.
         */
        SoarAuditEvent: {
            /**
             * Action
             * @enum {string}
             */
            action: "SOAR_RUN_REQUESTED" | "SOAR_RUN_STATE" | "SOAR_APPROVAL_REQUESTED" | "SOAR_APPROVAL_DECIDED" | "SOAR_STEP_EXECUTED" | "SOAR_STEP_RETRY_SCHEDULED" | "SOAR_LIVE_REFUSED";
            actor: components["schemas"]["ActorRef"];
            /** @default null */
            from_state: components["schemas"]["RunState"] | null;
            /**
             * Run Id
             * Format: uuid
             */
            run_id: string;
            /**
             * Step Key
             * @default null
             */
            step_key: string | null;
            /** @default null */
            to_state: components["schemas"]["RunState"] | null;
        };
        /**
         * SoarOperations
         * @description The operations centre view. `ai_analysis` entries are analysis only; execution entries come from the engine.
         */
        SoarOperations: {
            /** Approved Playbooks */
            approved_playbooks: number;
            /** Awaiting Approval */
            awaiting_approval: number;
            /** Completed 24H */
            completed_24h: number;
            /** Dispatched Without Receipt */
            dispatched_without_receipt: number;
            /** Emergency Reason */
            emergency_reason: string;
            /** Emergency Stop */
            emergency_stop: boolean;
            /** Failed 24H */
            failed_24h: number;
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /**
             * Human Intervention
             * @description Runs waiting for a person: approvals or re-dispatch
             */
            human_intervention: number;
            /** Live Enabled */
            live_enabled: boolean;
            /** Max Runs Per Hour */
            max_runs_per_hour: number;
            /** Pending Playbook Reviews */
            pending_playbook_reviews: number;
            /** Refused 24H */
            refused_24h: number;
            /** Running */
            running: number;
            /** Runs Last Hour */
            runs_last_hour: number;
            /** Timeline */
            timeline: components["schemas"]["SoarTimelineEntry"][];
        };
        /** SoarPolicyUpdate */
        SoarPolicyUpdate: {
            /** Allowed Actions */
            allowed_actions: components["schemas"]["ActionType"][];
            /** Allowed Agent Groups */
            allowed_agent_groups: string[];
            /**
             * Approval Ttl Minutes
             * @default 60
             */
            approval_ttl_minutes: number;
            /**
             * Live Enabled
             * @default false
             */
            live_enabled: boolean;
            /**
             * Max Dispatch Attempts
             * @default 3
             */
            max_dispatch_attempts: number;
            /**
             * Max Runs Per Hour
             * @default 20
             */
            max_runs_per_hour: number;
        };
        /**
         * SoarPolicyView
         * @description The organization's response authorization. Empty allow-lists = nothing consequential may run.
         */
        SoarPolicyView: {
            /** Allowed Actions */
            allowed_actions: components["schemas"]["ActionType"][];
            /** Allowed Agent Groups */
            allowed_agent_groups: string[];
            /** Approval Ttl Minutes */
            approval_ttl_minutes: number;
            /**
             * Emergency At
             * @default null
             */
            emergency_at: string | null;
            /**
             * Emergency Reason
             * @default
             */
            emergency_reason: string;
            /**
             * Emergency Stop
             * @description Consolidation: when on, no run starts and nothing is dispatched
             * @default false
             */
            emergency_stop: boolean;
            /** Live Enabled */
            live_enabled: boolean;
            /**
             * Max Dispatch Attempts
             * @default 3
             */
            max_dispatch_attempts: number;
            /**
             * Max Runs Per Hour
             * @default 20
             */
            max_runs_per_hour: number;
            /**
             * Updated At
             * @default null
             */
            updated_at: string | null;
        };
        /** SoarTimelineEntry */
        SoarTimelineEntry: {
            /** Action */
            action: string;
            /** Actor Label */
            actor_label: string;
            /**
             * At
             * Format: date-time
             */
            at: string;
            /**
             * Category
             * @enum {string}
             */
            category: "execution" | "approval" | "policy" | "playbook" | "ai_analysis";
            /**
             * Outcome
             * @enum {string}
             */
            outcome: "success" | "denied" | "failure" | "pending" | "refused";
            /** Resource Id */
            resource_id: string;
            /** Summary */
            summary: string;
        };
        /** SourceDefinition */
        SourceDefinition: {
            /**
             * Allowed Senders
             * @description CIDRs within the collector's site allowed to send; empty = none
             * @default []
             */
            allowed_senders: string[];
            /**
             * Listen Port
             * @default null
             */
            listen_port: number | null;
            /**
             * Path
             * @default null
             */
            path: string | null;
            /**
             * Source Id
             * Format: uuid
             */
            source_id: string;
            /**
             * Type
             * @enum {string}
             */
            type: "syslog_udp" | "syslog_tcp" | "syslog_tls" | "file" | "windows_event";
        };
        /** Statement */
        Statement: {
            /** Citation Ids */
            citation_ids: string[];
            /** Text */
            text: string;
        };
        /** StepView */
        StepView: {
            action: components["schemas"]["ActionType"];
            /**
             * Approval Id
             * @default null
             */
            approval_id: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Message */
            message: string;
            /** @default null */
            receipt: components["schemas"]["ExecutionReceipt"] | null;
            /**
             * Request Id
             * @default null
             */
            request_id: string | null;
            /**
             * State
             * @enum {string}
             */
            state: "pending" | "awaiting_approval" | "rejected" | "expired" | "dispatched" | "succeeded" | "failed" | "dry_run" | "skipped_not_configured" | "refused_by_policy";
            /** Step Key */
            step_key: string;
            /** Target */
            target: string | null;
        };
        /**
         * StixIngest
         * @description A STIX 2.1 bundle for the organization: uploaded by a user, or delivered by the Server 1 TAXII feeder (its
         *     organization-bound ti_feeder identity decides the organization; the body has none).
         */
        StixIngest: {
            /** Bundle */
            bundle: {
                [key: string]: unknown;
            };
            /**
             * Collection
             * @default
             */
            collection: string;
            /** Source */
            source: string;
        };
        /** StixIngestResult */
        StixIngestResult: {
            /** Indicators Imported */
            indicators_imported: number;
            /** Objects Received */
            objects_received: number;
            /** Objects Stored */
            objects_stored: number;
            /**
             * Rejected
             * @default []
             */
            rejected: string[];
            /** Relationships */
            relationships: number;
        };
        /** StoredAlert */
        StoredAlert: {
            /** Agent Id */
            agent_id: string;
            /** Agent Name */
            agent_name: string;
            /**
             * Asset Id
             * @description Consolidation: the canonical asset of the alert's agent
             * @default null
             */
            asset_id: string | null;
            /**
             * Assignee Id
             * @default null
             */
            assignee_id: string | null;
            /**
             * Assignee Label
             * @default null
             */
            assignee_label: string | null;
            /**
             * Case Id
             * @description The case this alert is linked to, if any (the most recently linked one when several)
             * @default null
             */
            case_id: string | null;
            /** External Id */
            external_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Log Source Id
             * @description The registered syslog or agentless source the alert came from (events of the Wazuh manager, agent 000), if any
             * @default null
             */
            log_source_id: string | null;
            /**
             * Log Source Name
             * @default null
             */
            log_source_name: string | null;
            /** Mitre Techniques */
            mitre_techniques: string[];
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            /**
             * Received At
             * Format: date-time
             */
            received_at: string;
            /** Rule Description */
            rule_description: string;
            /** Rule Id */
            rule_id: string;
            /** Rule Level */
            rule_level: number;
            severity: components["schemas"]["Severity"];
            /**
             * Source
             * @enum {string}
             */
            source: "wazuh" | "local_fixture";
            /** Src Ip */
            src_ip: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "new" | "acknowledged" | "in_progress" | "closed";
        };
        /** SubscriptionSet */
        SubscriptionSet: {
            /**
             * Notes
             * @default
             */
            notes: string;
            /**
             * Org Id
             * Format: uuid
             */
            org_id: string;
            /**
             * Plan Id
             * Format: uuid
             */
            plan_id: string;
            /**
             * Renews At
             * @default null
             */
            renews_at: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "trial" | "active" | "past_due" | "cancelled";
        };
        /** SyncRunList */
        SyncRunList: {
            /** Items */
            items: components["schemas"]["SyncRunView"][];
        };
        /** SyncRunView */
        SyncRunView: {
            /** Conflicts */
            conflicts: number;
            /** Created */
            created: number;
            /** Detail */
            detail: string;
            /**
             * Finished At
             * @default null
             */
            finished_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Observed */
            observed: number;
            /**
             * Outcome
             * @enum {string}
             */
            outcome: "completed" | "source_unconfigured" | "source_unavailable" | "failed";
            /** Requested Label */
            requested_label: string;
            /** Source */
            source: string;
            /** Source State */
            source_state: string;
            /**
             * Started At
             * Format: date-time
             */
            started_at: string;
            /** Updated */
            updated: number;
        };
        /**
         * TaskExecution
         * @description One step attempt, written by the SOAR worker (API reads). Unique (run_id, step_key, attempt).
         */
        TaskExecution: {
            action: components["schemas"]["ActionType"];
            /** Attempt */
            attempt: number;
            /**
             * Idempotency Key
             * @description Derived: <run idempotency key>:<step_key>; sent to connectors that support it
             */
            idempotency_key: string;
            mode: components["schemas"]["ExecutionMode"];
            /**
             * Run Id
             * Format: uuid
             */
            run_id: string;
            /**
             * Started At
             * Format: date-time
             */
            started_at: string;
            /** Step Key */
            step_key: string;
            /**
             * Target
             * @default null
             */
            target: string | null;
        };
        /** TeamCreate */
        TeamCreate: {
            /**
             * Description
             * @default
             */
            description: string;
            /** Name */
            name: string;
        };
        /** TeamList */
        TeamList: {
            /** Items */
            items: components["schemas"]["TeamView"][];
        };
        /** TeamMemberAdd */
        TeamMemberAdd: {
            /**
             * Team Role
             * @default member
             * @enum {string}
             */
            team_role: "lead" | "member";
            /**
             * User Id
             * Format: uuid
             */
            user_id: string;
        };
        /** TeamMemberView */
        TeamMemberView: {
            /** Email */
            email: string;
            /** Role */
            role: string;
            /**
             * Team Role
             * @enum {string}
             */
            team_role: "lead" | "member";
            /**
             * User Id
             * Format: uuid
             */
            user_id: string;
        };
        /** TeamView */
        TeamView: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Description */
            description: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Members */
            members: components["schemas"]["TeamMemberView"][];
            /** Name */
            name: string;
        };
        /** TelemetryAck */
        TelemetryAck: {
            /** Accepted */
            accepted: number;
            /** Batch Id */
            batch_id: string;
            /** Duplicates */
            duplicates: number;
            /**
             * Durable
             * @description An ack is only sent once the batch is durably stored
             * @default true
             * @constant
             */
            durable: true;
            /**
             * Quarantined
             * @description Stored but not attributable (e.g. sender outside the site's networks)
             */
            quarantined: number;
            /** Rejected */
            rejected: number;
        };
        /** TelemetryBatch */
        TelemetryBatch: {
            /**
             * Batch Id
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            batch_id: string;
            /** Events */
            events: components["schemas"]["TelemetryEvent"][];
            /**
             * Sent At
             * Format: date-time
             */
            sent_at: string;
        };
        /** TelemetryEvent */
        TelemetryEvent: {
            /**
             * Event Id
             * @description Collector-unique id; dedupe key with the identity
             */
            event_id: string;
            /**
             * Format
             * @enum {string}
             */
            format: "syslog_rfc5424" | "syslog_rfc3164" | "cef" | "leef" | "json" | "windows_xml";
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            /**
             * Raw
             * @description Raw event, capped at 32 KB (legacy ingest cap)
             */
            raw: string;
            sender: components["schemas"]["SiteScopedAddress"];
            /**
             * Source Id
             * Format: uuid
             */
            source_id: string;
        };
        /**
         * ThreatActorCreate
         * @description An actor profile. `verified` needs at least one cited source; `unknown` attribution carries confidence 0.
         *     Nothing is pre-loaded; NovrSOC never names an actor on its own.
         */
        ThreatActorCreate: {
            /**
             * Aliases
             * @default []
             */
            aliases: string[];
            /**
             * Attribution
             * @enum {string}
             */
            attribution: "verified" | "suspected" | "unknown";
            /**
             * Confidence
             * @default 0
             */
            confidence: number;
            /**
             * Description
             * @default
             */
            description: string;
            /**
             * First Seen
             * @default null
             */
            first_seen: string | null;
            /**
             * Last Seen
             * @default null
             */
            last_seen: string | null;
            /**
             * Motivations
             * @default []
             */
            motivations: string[];
            /** Name */
            name: string;
            /**
             * Sources
             * @default []
             */
            sources: components["schemas"]["ActorSource"][];
            /**
             * Target Regions
             * @default []
             */
            target_regions: string[];
            /**
             * Target Sectors
             * @default []
             */
            target_sectors: string[];
            /**
             * Techniques
             * @default []
             */
            techniques: string[];
        };
        /** ThreatActorList */
        ThreatActorList: {
            /** Items */
            items: components["schemas"]["ThreatActorView"][];
        };
        /** ThreatActorView */
        ThreatActorView: {
            /**
             * Aliases
             * @default []
             */
            aliases: string[];
            /**
             * Attribution
             * @enum {string}
             */
            attribution: "verified" | "suspected" | "unknown";
            /**
             * Confidence
             * @default 0
             */
            confidence: number;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Created Label */
            created_label: string;
            /**
             * Description
             * @default
             */
            description: string;
            /**
             * First Seen
             * @default null
             */
            first_seen: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Last Seen
             * @default null
             */
            last_seen: string | null;
            /**
             * Links
             * @default []
             */
            links: components["schemas"]["ActorLinkView"][];
            /**
             * Motivations
             * @default []
             */
            motivations: string[];
            /** Name */
            name: string;
            /**
             * Observed In Organization
             * @description True only when a VERIFIED link ties the actor to this organization's own records
             * @default false
             */
            observed_in_organization: boolean;
            /**
             * Sources
             * @default []
             */
            sources: components["schemas"]["ActorSource"][];
            /**
             * Target Regions
             * @default []
             */
            target_regions: string[];
            /**
             * Target Sectors
             * @default []
             */
            target_sectors: string[];
            /**
             * Techniques
             * @default []
             */
            techniques: string[];
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** Timestamped */
        Timestamped: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
        };
        /**
         * Tlp
         * @enum {string}
         */
        Tlp: "clear" | "green" | "amber" | "amber_strict" | "red";
        /** TrendPoint */
        TrendPoint: {
            /**
             * Period Start
             * Format: date
             */
            period_start: string;
            /** Values */
            values: {
                [key: string]: number;
            };
        };
        /**
         * UsageEvent
         * @description One per gateway request (allowed or rejected). Prompt and output TEXT are never stored here;
         *     a SHA-256 of the prompt allows correlation without retaining content.
         */
        UsageEvent: {
            /**
             * Completion Tokens
             * @default 0
             */
            completion_tokens: number;
            /**
             * Key Id
             * @default null
             */
            key_id: string | null;
            lane: components["schemas"]["Lane"];
            /**
             * Latency Ms
             * @default 0
             */
            latency_ms: number;
            /** Model */
            model: string;
            /**
             * Occurred At
             * Format: date-time
             */
            occurred_at: string;
            /**
             * Org Id
             * @default null
             */
            org_id: string | null;
            /**
             * Outcome
             * @enum {string}
             */
            outcome: "ok" | "rejected" | "timeout" | "backend_error";
            /**
             * Prompt Sha256
             * @default null
             */
            prompt_sha256: string | null;
            /**
             * Prompt Tokens
             * @default 0
             */
            prompt_tokens: number;
            /** @default null */
            reject_reason: components["schemas"]["RejectReason"] | null;
            /** Request Id */
            request_id: string;
            /**
             * User Id
             * @default null
             */
            user_id: string | null;
        };
        /** UserRef */
        UserRef: {
            /** Email */
            email: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Role */
            role: string;
        };
        /** UserSearchList */
        UserSearchList: {
            /** Items */
            items: components["schemas"]["UserSearchResult"][];
        };
        /** UserSearchResult */
        UserSearchResult: {
            /** Display Name */
            display_name: string;
            /** Email */
            email: string;
            /**
             * Home Org Id
             * @default null
             */
            home_org_id: string | null;
            /**
             * Home Org Name
             * @default null
             */
            home_org_name: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Memberships
             * @default []
             */
            memberships: components["schemas"]["MembershipView"][];
            /**
             * Role
             * @default null
             */
            role: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "disabled";
        };
        /** UserStatusUpdate */
        UserStatusUpdate: {
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "disabled";
        };
        /** UserSummary */
        UserSummary: {
            /** Display Name */
            display_name: string;
            /** Email */
            email: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
        };
        /**
         * VerificationRecord
         * @description Verification history entry: only a completed, in-scope scan job may verify or reopen a finding.
         */
        VerificationRecord: {
            /**
             * Checked At
             * Format: date-time
             */
            checked_at: string;
            /**
             * Evidence Ref
             * @default null
             */
            evidence_ref: string | null;
            /**
             * Finding Id
             * Format: uuid
             */
            finding_id: string;
            /**
             * Result
             * @enum {string}
             */
            result: "verified_fixed" | "still_present" | "inconclusive";
            /**
             * Scan Job Id
             * Format: uuid
             */
            scan_job_id: string;
        };
        /** VerificationRequestView */
        VerificationRequestView: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Note */
            note: string;
            /** Requested Label */
            requested_label: string;
            /**
             * Scan Job Id
             * @default null
             */
            scan_job_id: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "scan_requested" | "blocked_scanning_disabled" | "blocked_no_scope" | "verified" | "still_present" | "cancelled";
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /** VmsEnrollmentEvaluation */
        VmsEnrollmentEvaluation: {
            /** By Status */
            by_status: {
                [key: string]: number;
            };
            /** Evaluated */
            evaluated: number;
            /**
             * Scans Queued
             * @default 0
             */
            scans_queued: number;
        };
        /** VmsEnrollmentExclusion */
        VmsEnrollmentExclusion: {
            /** Excluded */
            excluded: boolean;
            /** Reason */
            reason: string;
        };
        /** VmsEnrollmentList */
        VmsEnrollmentList: {
            /** By Status */
            by_status: {
                [key: string]: number;
            };
            /**
             * Evaluated At
             * @default null
             */
            evaluated_at: string | null;
            /** Items */
            items: components["schemas"]["VmsEnrollmentView"][];
        };
        /** VmsEnrollmentView */
        VmsEnrollmentView: {
            /**
             * Address
             * @default null
             */
            address: string | null;
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
            /** Asset Name */
            asset_name: string;
            /**
             * Evaluated At
             * Format: date-time
             */
            evaluated_at: string;
            /**
             * Hostname
             * @default null
             */
            hostname: string | null;
            /**
             * Last Job Id
             * @default null
             */
            last_job_id: string | null;
            /**
             * Last Scanned At
             * @default null
             */
            last_scanned_at: string | null;
            /**
             * Open Findings
             * @default 0
             */
            open_findings: number;
            /** Reason */
            reason: string;
            /**
             * Scope Id
             * @default null
             */
            scope_id: string | null;
            /**
             * Scope Value
             * @default null
             */
            scope_value: string | null;
            /**
             * Sources
             * @default []
             */
            sources: string[];
            /**
             * Status
             * @enum {string}
             */
            status: "enrolled" | "eligible" | "excluded_protected" | "outside_scope" | "public_address" | "shared_address" | "stale_address" | "no_address" | "unverified_source" | "manual_exclusion";
        };
        /** VmsFindingDetail */
        VmsFindingDetail: {
            /**
             * Cve Intel
             * @default []
             */
            cve_intel: components["schemas"]["FindingCveIntel"][];
            /**
             * Cves Without Intel
             * @default []
             */
            cves_without_intel: string[];
            finding: components["schemas"]["VmsFindingView"];
            /**
             * History
             * @default []
             */
            history: {
                [key: string]: unknown;
            }[];
            /** @default null */
            remediation: components["schemas"]["RemediationTaskView"] | null;
            /**
             * Verifications
             * @default []
             */
            verifications: components["schemas"]["VerificationRequestView"][];
        };
        /** VmsFindingList */
        VmsFindingList: {
            /** Items */
            items: components["schemas"]["VmsFindingView"][];
            /** Total */
            total: number;
        };
        /** VmsFindingView */
        VmsFindingView: {
            /**
             * Asset Id
             * @description Consolidation: the canonical asset of the host
             * @default null
             */
            asset_id: string | null;
            /**
             * Asset Name
             * @default null
             */
            asset_name: string | null;
            /**
             * Check Id
             * @default null
             */
            check_id: string | null;
            /**
             * Cves
             * @default []
             */
            cves: string[];
            /**
             * First Seen At
             * Format: date-time
             */
            first_seen_at: string;
            /** Host */
            host: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Kev
             * @description Consolidation: a CVE of the finding is in the organization's KEV intelligence
             * @default false
             */
            kev: boolean;
            /**
             * Last Seen At
             * Format: date-time
             */
            last_seen_at: string;
            /** Occurrences */
            occurrences: number;
            /**
             * Port
             * @default null
             */
            port: number | null;
            /**
             * Priority
             * @enum {string}
             */
            priority: "P1" | "P2" | "P3" | "P4";
            /**
             * Protocol
             * @default null
             */
            protocol: string | null;
            /**
             * Remediation Due At
             * @default null
             */
            remediation_due_at: string | null;
            risk: components["schemas"]["RiskScore"];
            severity: components["schemas"]["Severity"];
            /** Source */
            source: string;
            status: components["schemas"]["FindingStatus"];
            /** Title */
            title: string;
        };
        /** VmsReport */
        VmsReport: {
            /** By Priority */
            by_priority: {
                [key: string]: number;
            };
            /** By Severity */
            by_severity: {
                [key: string]: number;
            };
            /** By Status */
            by_status: {
                [key: string]: number;
            };
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Overdue Remediation */
            overdue_remediation: number;
            /**
             * Scanning
             * @enum {string}
             */
            scanning: "disabled" | "enabled";
            /** Scans Completed 30D */
            scans_completed_30d: number;
            /** Top Findings */
            top_findings: components["schemas"]["VmsFindingView"][];
        };
        /** VmsResultAck */
        VmsResultAck: {
            /** Batch Id */
            batch_id: string;
            /** New Findings */
            new_findings: number;
            /** Observations */
            observations: number;
            /** Refused Out Of Scope */
            refused_out_of_scope: number;
            /**
             * Replayed
             * @default false
             */
            replayed: boolean;
            /** Updated Findings */
            updated_findings: number;
        };
        /** VmsRiskOverview */
        VmsRiskOverview: {
            /** Assets */
            assets: components["schemas"]["RiskAssetRow"][];
            /** By Priority */
            by_priority: {
                [key: string]: number;
            };
            /** By Severity */
            by_severity: {
                [key: string]: number;
            };
            /** Formula */
            formula: string;
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            /** Internet Facing Findings */
            internet_facing_findings: number;
            /** Kev Findings */
            kev_findings: number;
            /** Overdue */
            overdue: number;
        };
        /** VmsScanCreate */
        VmsScanCreate: {
            activity: components["schemas"]["ScanActivity"];
            /**
             * Idempotency Key
             * @description Client-chosen key; a repeat with the same key returns the first result
             */
            idempotency_key: string;
            /**
             * Profile
             * @default standard
             * @enum {string}
             */
            profile: "discovery" | "standard" | "full";
            /**
             * Scope Id
             * Format: uuid
             */
            scope_id: string;
            /** Targets */
            targets: string[];
        };
        /** VmsScanList */
        VmsScanList: {
            /** Items */
            items: components["schemas"]["VmsScanView"][];
        };
        /** VmsScanPolicy */
        VmsScanPolicy: {
            /**
             * Address Max Age Hours
             * @default 72
             */
            address_max_age_hours: number;
            /**
             * Authorization Reference
             * @default
             */
            authorization_reference: string;
            /**
             * Auto Enroll
             * @default false
             */
            auto_enroll: boolean;
            /**
             * Configured
             * @description False until the organization saves a policy (the defaults shown are not in force)
             */
            configured: boolean;
            /** Enabled */
            enabled: boolean;
            /** @default ports */
            enroll_activity: components["schemas"]["ScanActivity"];
            /** In Window Now */
            in_window_now: boolean;
            /**
             * Installation Mode
             * @enum {string}
             */
            installation_mode: "disabled" | "local_test_targets" | "authorized_scopes";
            /**
             * Max Concurrent Scans
             * @default 1
             */
            max_concurrent_scans: number;
            /**
             * Max Rate Pps
             * @default 100
             */
            max_rate_pps: number;
            /**
             * Max Targets Per Scan
             * @default 32
             */
            max_targets_per_scan: number;
            /**
             * Protected Networks
             * @default []
             */
            protected_networks: string[];
            /**
             * Rescan Interval Days
             * @default 7
             */
            rescan_interval_days: number;
            /**
             * Timezone
             * @default UTC
             */
            timezone: string;
            /**
             * Updated At
             * @default null
             */
            updated_at: string | null;
            /**
             * Updated By Label
             * @default null
             */
            updated_by_label: string | null;
            /**
             * Windows
             * @default []
             */
            windows: components["schemas"]["PolicyWindow"][];
        };
        /**
         * VmsScanPolicyUpdate
         * @description The organization's standing scan authorization (vms:scope). Enabling requires an authorization reference and at
         *     least one window. auto_enroll enrolls imported assets that fall inside an approved scope; it never widens a scope.
         */
        VmsScanPolicyUpdate: {
            /**
             * Address Max Age Hours
             * @default 72
             */
            address_max_age_hours: number;
            /**
             * Authorization Reference
             * @default
             */
            authorization_reference: string;
            /**
             * Auto Enroll
             * @default false
             */
            auto_enroll: boolean;
            /** Enabled */
            enabled: boolean;
            /** @default ports */
            enroll_activity: components["schemas"]["ScanActivity"];
            /**
             * Max Concurrent Scans
             * @default 1
             */
            max_concurrent_scans: number;
            /**
             * Max Rate Pps
             * @default 100
             */
            max_rate_pps: number;
            /**
             * Max Targets Per Scan
             * @default 32
             */
            max_targets_per_scan: number;
            /**
             * Protected Networks
             * @default []
             */
            protected_networks: string[];
            /**
             * Rescan Interval Days
             * @default 7
             */
            rescan_interval_days: number;
            /**
             * Timezone
             * @default UTC
             */
            timezone: string;
            /**
             * Windows
             * @default []
             */
            windows: components["schemas"]["PolicyWindow"][];
        };
        /** VmsScanView */
        VmsScanView: {
            activity: components["schemas"]["ScanActivity"];
            /**
             * Asset Ids
             * @default []
             */
            asset_ids: string[];
            /**
             * Claimed At
             * @default null
             */
            claimed_at: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Error
             * @default null
             */
            error: string | null;
            /**
             * Finished At
             * @default null
             */
            finished_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Origin
             * @default manual
             * @enum {string}
             */
            origin: "manual" | "schedule" | "rescan" | "enrollment";
            /**
             * Outcome
             * @default {}
             */
            outcome: {
                [key: string]: unknown;
            };
            /**
             * Progress
             * @description targets_total, targets_reported, per-target outcomes, observations
             * @default {}
             */
            progress: {
                [key: string]: unknown;
            };
            /**
             * Scope Id
             * Format: uuid
             */
            scope_id: string;
            /**
             * State
             * @enum {string}
             */
            state: "queued" | "running" | "completed" | "failed" | "cancelled";
            /** Targets */
            targets: string[];
        };
        /** VmsScheduleCreate */
        VmsScheduleCreate: {
            activity: components["schemas"]["ScanActivity"];
            /**
             * Cadence
             * @enum {string}
             */
            cadence: "daily" | "weekly" | "monthly";
            /**
             * Enabled
             * @default false
             */
            enabled: boolean;
            /** Name */
            name: string;
            /**
             * Scope Id
             * Format: uuid
             */
            scope_id: string;
            /** Targets */
            targets: string[];
        };
        /** VmsScheduleList */
        VmsScheduleList: {
            /** Items */
            items: components["schemas"]["VmsScheduleView"][];
        };
        /** VmsScheduleUpdate */
        VmsScheduleUpdate: {
            /** Enabled */
            enabled: boolean;
        };
        /** VmsScheduleView */
        VmsScheduleView: {
            /** Activity */
            activity: string;
            /** Cadence */
            cadence: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Enabled */
            enabled: boolean;
            /** Execution */
            execution: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Last Job Id
             * @default null
             */
            last_job_id: string | null;
            /** Name */
            name: string;
            /**
             * Next Run At
             * Format: date-time
             */
            next_run_at: string;
            /**
             * Scope Id
             * Format: uuid
             */
            scope_id: string;
            /** Targets */
            targets: string[];
        };
        /**
         * VmsScopeCreate
         * @description Human API (vms:scope). An approved scope is the only thing a scan may touch.
         */
        VmsScopeCreate: {
            /** Allowed Activities */
            allowed_activities: components["schemas"]["ScanActivity"][];
            /** Authorization Reference */
            authorization_reference: string;
            entry: components["schemas"]["ScopeEntry"];
            /**
             * Valid Days
             * @default 30
             */
            valid_days: number;
        };
        /** VmsScopeList */
        VmsScopeList: {
            /** Items */
            items: components["schemas"]["VmsScopeView"][];
        };
        /** VmsScopeView */
        VmsScopeView: {
            /** Allowed Activities */
            allowed_activities: components["schemas"]["ScanActivity"][];
            /** Authorization Reference */
            authorization_reference: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            entry: components["schemas"]["ScopeEntry"];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Valid Until
             * Format: date-time
             */
            valid_until: string;
        };
        /**
         * VmsStatus
         * @description VMS readiness for the active organization: whether scanning may run and which V2 workers have reported.
         */
        VmsStatus: {
            /** Reason */
            reason: string;
            /**
             * Scanning
             * @enum {string}
             */
            scanning: "disabled" | "enabled";
            /**
             * Workers
             * @default []
             */
            workers: components["schemas"]["VmsWorkerStatus"][];
        };
        /** VmsWorkerStatus */
        VmsWorkerStatus: {
            /** Component Version */
            component_version: string;
            /** Identity Name */
            identity_name: string;
            /**
             * Last Heartbeat At
             * Format: date-time
             */
            last_heartbeat_at: string;
            /** Stale */
            stale: boolean;
            /**
             * State
             * @enum {string}
             */
            state: "ok" | "degraded" | "failing" | "unconfigured";
        };
        /** VulnerabilitySummary */
        VulnerabilitySummary: {
            /**
             * Critical
             * @default null
             */
            critical: number | null;
            /**
             * High
             * @default null
             */
            high: number | null;
            /**
             * Low
             * @default null
             */
            low: number | null;
            /**
             * Medium
             * @default null
             */
            medium: number | null;
            source: components["schemas"]["ConnectorState"];
            /**
             * Total
             * @description null when the source is unavailable; never a guessed 0
             * @default null
             */
            total: number | null;
        };
        /** WatchSubject */
        WatchSubject: {
            /**
             * Active
             * @default true
             */
            active: boolean;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            type: components["schemas"]["WatchSubjectType"];
            /** Value */
            value: string;
        };
        /** WatchSubjectCreate */
        WatchSubjectCreate: {
            /**
             * Consent Reference
             * @description Required for EXECUTIVE subjects (personal data, NDPA)
             * @default null
             */
            consent_reference: string | null;
            type: components["schemas"]["WatchSubjectType"];
            /** Value */
            value: string;
        };
        /** WatchSubjectList */
        WatchSubjectList: {
            /** Items */
            items: components["schemas"]["WatchSubject"][];
        };
        /**
         * WatchSubjectType
         * @enum {string}
         */
        WatchSubjectType: "brand_name" | "domain" | "executive" | "social_account" | "mobile_app" | "code_repository_term";
        /**
         * WazuhAgentContext
         * @description What the Wazuh connector reports for the asset's agent. `source` says where it came from (local fixture, live,
         *     unconfigured or unavailable). Wazuh vulnerability detection is a separate method from VMS scanning.
         */
        WazuhAgentContext: {
            /** Agent Id */
            agent_id: string;
            /**
             * Agent Version
             * @default null
             */
            agent_version: string | null;
            /**
             * Groups
             * @default []
             */
            groups: string[];
            /**
             * Last Keepalive At
             * @default null
             */
            last_keepalive_at: string | null;
            /**
             * Name
             * @default null
             */
            name: string | null;
            /** @default null */
            sca: components["schemas"]["ScaSummary"] | null;
            source: components["schemas"]["ConnectorState"];
            /**
             * Status
             * @default null
             */
            status: string | null;
            /** @default null */
            vulnerabilities: components["schemas"]["VulnerabilitySummary"] | null;
        };
        /** WazuhAgentRef */
        WazuhAgentRef: {
            /**
             * Groups
             * @default []
             */
            groups: string[];
            /** Id */
            id: string;
            /**
             * Name
             * @default
             */
            name: string;
        };
        /** WazuhAlertIn */
        WazuhAlertIn: {
            agent: components["schemas"]["WazuhAgentRef"];
            /**
             * Id
             * @description Wazuh alert id; dedupe key per organization
             */
            id: string;
            /**
             * Raw
             * @description Original alert; stored capped at 32 KB
             * @default {}
             */
            raw: {
                [key: string]: unknown;
            };
            rule: components["schemas"]["WazuhRule"];
            /**
             * Src Ip
             * @default null
             */
            src_ip: string | null;
            /**
             * Timestamp
             * Format: date-time
             */
            timestamp: string;
        };
        /**
         * WazuhEndpoint
         * @description Read model of a Wazuh agent mapped to an asset. Ownership comes from the group/source map, never the agent.
         */
        WazuhEndpoint: {
            /** Agent Id */
            agent_id: string;
            /**
             * Agent Version
             * @default null
             */
            agent_version: string | null;
            /**
             * Asset Id
             * Format: uuid
             */
            asset_id: string;
            /**
             * Groups
             * @default []
             */
            groups: string[];
            /**
             * Last Keepalive At
             * @default null
             */
            last_keepalive_at: string | null;
            /**
             * Manager Id
             * Format: uuid
             */
            manager_id: string;
            /** Name */
            name: string;
            /**
             * Os Platform
             * @default null
             */
            os_platform: string | null;
            /**
             * Os Version
             * @default null
             */
            os_version: string | null;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "disconnected" | "never_connected" | "pending";
        };
        /** WazuhRule */
        WazuhRule: {
            /**
             * Description
             * @default
             */
            description: string;
            /** Id */
            id: string;
            /** Level */
            level: number;
            /**
             * Mitre Ids
             * @default []
             */
            mitre_ids: string[];
        };
        /** WorkerFinish */
        WorkerFinish: {
            /**
             * Detail
             * @default
             */
            detail: string;
            /**
             * Outcome
             * @enum {string}
             */
            outcome: "completed" | "failed";
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export type operations = Record<string, never>;
