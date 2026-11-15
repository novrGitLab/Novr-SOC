// GENERATED from packages/contracts/openapi/novrsoc-api.v1.json by scripts/check-api-types.mjs. Do not edit.
// Regenerate: npm run api:types (after scripts/contracts/export.py).

export interface paths {
    "/api/v1/admin/analytics": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Platform analytics across organizations (counts only) */
        get: operations["analytics_api_v1_admin_analytics_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/backups": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Backup runs and their latest restore drill */
        get: operations["list_backups_api_v1_admin_backups_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/billing": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Plans, subscriptions and usage (no payment provider is configured) */
        get: operations["billing_api_v1_admin_billing_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/billing/plans": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Create a billing plan */
        post: operations["create_plan_api_v1_admin_billing_plans_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/billing/plans/{plan_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        /** Activate or retire a plan */
        patch: operations["update_plan_api_v1_admin_billing_plans__plan_id__patch"];
        trace?: never;
    };
    "/api/v1/admin/billing/subscriptions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Set an organization's plan and subscription status */
        put: operations["set_subscription_api_v1_admin_billing_subscriptions_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/exports": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Authorized data exports of the active organization */
        get: operations["list_exports_api_v1_admin_exports_get"];
        put?: never;
        /** Create an authorized export (justification and recipient required) */
        post: operations["create_export_api_v1_admin_exports_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/exports/{export_id}/download": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Download an export (audited; refused once expired or revoked) */
        get: operations["download_export_api_v1_admin_exports__export_id__download_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/exports/{export_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke an export (it can no longer be downloaded) */
        post: operations["revoke_export_api_v1_admin_exports__export_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/health": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Platform health: measured component states, queues, workers and failures */
        get: operations["health_api_v1_admin_health_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/onboarding": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Onboarding progress of the active organization */
        get: operations["onboarding_api_v1_admin_onboarding_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/organizations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** All organizations (platform administrators) */
        get: operations["list_orgs_api_v1_admin_organizations_get"];
        put?: never;
        /** Create a client organization */
        post: operations["create_org_api_v1_admin_organizations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/service-identities": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Machine identities of the active organization */
        get: operations["list_identities_api_v1_admin_service_identities_get"];
        put?: never;
        /** Issue a machine credential (shown once) */
        post: operations["issue_identity_api_v1_admin_service_identities_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/service-identities/{identity_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke a machine credential */
        post: operations["revoke_identity_api_v1_admin_service_identities__identity_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/teams": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Analyst teams of the active organization */
        get: operations["list_teams_api_v1_admin_teams_get"];
        put?: never;
        /** Create a team */
        post: operations["create_team_api_v1_admin_teams_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/teams/{team_id}/members": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Add a member of the organization to a team */
        post: operations["add_member_api_v1_admin_teams__team_id__members_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/teams/{team_id}/members/{user_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Remove a member from a team */
        delete: operations["remove_member_api_v1_admin_teams__team_id__members__user_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/users": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Users with a membership in the active organization */
        get: operations["list_users_api_v1_admin_users_get"];
        put?: never;
        /** Create a user in the active organization */
        post: operations["create_user_api_v1_admin_users_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/users/{user_id}/memberships": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** A user's organizations (home and assignments) */
        get: operations["list_memberships_api_v1_admin_users__user_id__memberships_get"];
        put?: never;
        /** Assign a user to another organization (analyst onboarding) */
        post: operations["grant_membership_api_v1_admin_users__user_id__memberships_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/users/{user_id}/memberships/{org_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Remove an assignment (never the home membership) */
        delete: operations["revoke_membership_api_v1_admin_users__user_id__memberships__org_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/users/{user_id}/reset-password": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Issue a new temporary password (shown once; sessions revoked; must be changed at sign-in) */
        post: operations["reset_password_api_v1_admin_users__user_id__reset_password_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/users/{user_id}/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Disable or re-enable a user (sessions revoked on disable) */
        post: operations["set_status_api_v1_admin_users__user_id__status_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/admin/wazuh/quarantine": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Alerts quarantined because no organization maps their groups */
        get: operations["quarantine_api_v1_admin_wazuh_quarantine_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/assets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Unified asset inventory of the active organization */
        get: operations["list_assets_api_v1_assets_get"];
        put?: never;
        /** Add an asset (reconciled: an existing identity is reused) */
        post: operations["create_asset_api_v1_assets_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/assets/collectors": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Collector and discovery settings */
        get: operations["list_collectors_api_v1_assets_collectors_get"];
        put?: never;
        /** Add a collector or discovery configuration (disabled) */
        post: operations["create_collector_api_v1_assets_collectors_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/assets/collectors/{collector_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Remove a collector configuration */
        delete: operations["delete_collector_api_v1_assets_collectors__collector_id__delete"];
        options?: never;
        head?: never;
        /** Change a collector (enabling discovery needs an authorization) */
        patch: operations["update_collector_api_v1_assets_collectors__collector_id__patch"];
        trace?: never;
    };
    "/api/v1/assets/collectors/{collector_id}/run": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Run a collector now (what runs depends on its kind) */
        post: operations["run_collector_api_v1_assets_collectors__collector_id__run_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/assets/conflicts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Identifier conflicts waiting for an analyst (merge or ignore) */
        get: operations["conflicts_api_v1_assets_conflicts_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/assets/import": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Import assets (manual list, up to 500 rows), reconciled */
        post: operations["import_assets_api_v1_assets_import_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/assets/sync-runs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Reconciliation runs (newest first) */
        get: operations["sync_runs_api_v1_assets_sync_runs_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/assets/sync/wazuh": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reconcile the organization's Wazuh agents into the inventory */
        post: operations["run_wazuh_sync_api_v1_assets_sync_wazuh_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/assets/{asset_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One asset across SIEM, VMS, cases, SOAR and intelligence */
        get: operations["detail_api_v1_assets__asset_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        /** Classify or update an asset */
        patch: operations["update_asset_api_v1_assets__asset_id__patch"];
        trace?: never;
    };
    "/api/v1/assets/{asset_id}/merge": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Merge another asset into this one (deduplication) */
        post: operations["merge_asset_api_v1_assets__asset_id__merge_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/assets/{asset_id}/retire": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Retire an asset (kept with its history) */
        post: operations["retire_asset_api_v1_assets__asset_id__retire_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/audit/events": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Audit events of the active organization */
        get: operations["list_audit_api_v1_audit_events_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/login": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Sign in (sets an httpOnly session cookie) */
        post: operations["login_api_v1_auth_login_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/logout": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke the current session */
        post: operations["logout_api_v1_auth_logout_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/me": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The signed-in user, role, active organization and permissions */
        get: operations["me_api_v1_auth_me_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/password": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change your password (other sessions are revoked) */
        post: operations["change_password_api_v1_auth_password_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/chat/conversations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The signed-in user's NovrChat conversations */
        get: operations["conversations_api_v1_chat_conversations_get"];
        put?: never;
        /** Start a conversation */
        post: operations["start_api_v1_chat_conversations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/chat/conversations/{conversation_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One conversation with its messages */
        get: operations["get_conversation_api_v1_chat_conversations__conversation_id__get"];
        put?: never;
        post?: never;
        /** Delete a conversation (audited) */
        delete: operations["delete_conversation_api_v1_chat_conversations__conversation_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/chat/conversations/{conversation_id}/messages": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Ask a question; the answer cites the records it used */
        post: operations["ask_api_v1_chat_conversations__conversation_id__messages_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/access": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** CNII access check: needs cnii:read AND an active designation for the sector */
        get: operations["cnii_access_api_v1_cnii_access_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/authorizations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Monitoring authorization records (designated sectors only) */
        get: operations["list_authorizations_api_v1_cnii_authorizations_get"];
        put?: never;
        /** Record a monitoring authorization */
        post: operations["create_authorization_api_v1_cnii_authorizations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/authorizations/{authorization_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke an authorization (its assets' schedules stop) */
        post: operations["revoke_authorization_api_v1_cnii_authorizations__authorization_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/designations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** All CNII designations (platform administrators) */
        get: operations["all_designations_api_v1_cnii_designations_get"];
        put?: never;
        /** Grant a CNII designation (always expires) */
        post: operations["grant_api_v1_cnii_designations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/designations/mine": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The signed-in user's CNII designations */
        get: operations["mine_api_v1_cnii_designations_mine_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/designations/{designation_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke a CNII designation */
        post: operations["revoke_api_v1_cnii_designations__designation_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/monitored-assets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Designated CNII assets (designated sectors only) */
        get: operations["list_monitored_api_v1_cnii_monitored_assets_get"];
        put?: never;
        /** Designate an asset for CNII monitoring (needs an active authorization covering the sector) */
        post: operations["designate_asset_api_v1_cnii_monitored_assets_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/monitored-assets/{monitored_id}/checks": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Recorded checks (newest first) */
        get: operations["checks_api_v1_cnii_monitored_assets__monitored_id__checks_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/monitored-assets/{monitored_id}/schedule": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Set a monitoring schedule */
        put: operations["set_schedule_api_v1_cnii_monitored_assets__monitored_id__schedule_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/monitored-assets/{monitored_id}/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Suspend or resume monitoring */
        post: operations["set_monitored_status_api_v1_cnii_monitored_assets__monitored_id__status_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/overview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** CNII monitoring overview of the active organization (designated sectors) */
        get: operations["overview_api_v1_cnii_overview_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/profiles": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Organization CNII profiles (platform administrators) */
        get: operations["profiles_api_v1_cnii_profiles_get"];
        /** Set an organization's CNII sectors and criticality */
        put: operations["set_profile_api_v1_cnii_profiles_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cnii/sector-overview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Sector overview (permission AND designation) */
        get: operations["sector_overview_api_v1_cnii_sector_overview_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/continuity/overview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Continuity overview: backups, plans, requests, RPO and RTO */
        get: operations["overview_api_v1_continuity_overview_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/continuity/plans": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Recovery plans of the organization */
        get: operations["list_plans_api_v1_continuity_plans_get"];
        put?: never;
        /** Create a recovery plan */
        post: operations["create_plan_api_v1_continuity_plans_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/continuity/plans/{plan_id}/tested": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Record that a plan was tested */
        post: operations["plan_tested_api_v1_continuity_plans__plan_id__tested_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/continuity/requests": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Recovery requests (newest first) */
        get: operations["list_requests_api_v1_continuity_requests_get"];
        put?: never;
        /** Submit a recovery request */
        post: operations["create_request_api_v1_continuity_requests_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/continuity/requests/{request_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One recovery request with its events */
        get: operations["get_request_api_v1_continuity_requests__request_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/continuity/requests/{request_id}/decision": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Assess, approve, reject or declare not recoverable */
        post: operations["decide_api_v1_continuity_requests__request_id__decision_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/continuity/requests/{request_id}/progress": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Record recovery progress or completion */
        post: operations["progress_api_v1_continuity_requests__request_id__progress_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/continuity/requests/{request_id}/verify": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Verify a completed recovery (not the requester) */
        post: operations["verify_api_v1_continuity_requests__request_id__verify_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/endpoints": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Endpoint inventory of the active organization */
        get: operations["inventory_api_v1_endpoints_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/endpoints/group-mappings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Wazuh agent groups mapped to the organization */
        get: operations["list_mappings_api_v1_endpoints_group_mappings_get"];
        put?: never;
        /** Map a Wazuh agent group to the organization */
        post: operations["create_mapping_api_v1_endpoints_group_mappings_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/endpoints/group-mappings/{mapping_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Remove a Wazuh agent group mapping */
        delete: operations["delete_mapping_api_v1_endpoints_group_mappings__mapping_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/endpoints/{agent_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One endpoint: health, OS, vulnerability and SCA summaries */
        get: operations["detail_api_v1_endpoints__agent_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/actors": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Threat actor profiles of the organization (nothing pre-loaded) */
        get: operations["list_actors_api_v1_insights_actors_get"];
        put?: never;
        /** Record a threat actor profile */
        post: operations["create_actor_api_v1_insights_actors_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/actors/{actor_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Update a threat actor profile */
        put: operations["update_actor_api_v1_insights_actors__actor_id__put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/actors/{actor_id}/links": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Associate an actor with an indicator, CVE, case, alert or asset (verified or suspected, with a rationale) */
        post: operations["link_actor_api_v1_insights_actors__actor_id__links_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/actors/{actor_id}/links/{link_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Remove an actor association */
        delete: operations["unlink_actor_api_v1_insights_actors__actor_id__links__link_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/correlations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Correlation groups over the organization's alerts */
        get: operations["correlations_api_v1_insights_correlations_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/cves": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** CVE intelligence, correlated with the organization's open findings */
        get: operations["list_cves_api_v1_insights_cves_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/cves/import": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Import CVE intelligence (records, or a CISA KEV catalog file) */
        post: operations["import_cves_api_v1_insights_cves_import_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/cves/import-stix": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Derive CVE records from STIX 2.1 vulnerability objects already stored */
        post: operations["import_cves_from_stix_api_v1_insights_cves_import_stix_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/feed-runs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Recent STIX/TAXII ingest runs */
        get: operations["feed_runs_api_v1_insights_feed_runs_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/indicators": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Indicators of the active organization */
        get: operations["list_indicators_api_v1_insights_indicators_get"];
        put?: never;
        /** Import indicators (plain or a STIX 2.1 bundle) */
        post: operations["import_indicators_api_v1_insights_indicators_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/indicators/{indicator_id}/context": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** STIX relationship context of an indicator */
        get: operations["indicator_context_api_v1_insights_indicators__indicator_id__context_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/ingest/stix": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** TAXII feeder (machine identity): deliver a STIX 2.1 bundle */
        post: operations["feeder_ingest_api_v1_insights_ingest_stix_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/match": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Match indicators against the organization's recent alerts */
        post: operations["run_match_api_v1_insights_match_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/matches": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Indicator matches in the organization's alerts */
        get: operations["list_matches_api_v1_insights_matches_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/matches/{match_id}/verdict": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Analyst verdict on a match */
        post: operations["set_verdict_api_v1_insights_matches__match_id__verdict_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/snapshots": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Evidence snapshots (newest first) */
        get: operations["list_snapshots_api_v1_insights_snapshots_get"];
        put?: never;
        /** Freeze the current CVSS (per CVE) or IOC (per indicator) state as evidence, with a checksum */
        post: operations["create_snapshot_api_v1_insights_snapshots_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/stix": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** STIX 2.1 bundle: the organization's indicators and sightings in its alerts */
        get: operations["stix_export_api_v1_insights_stix_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/insights/stix/bundles": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Upload a STIX 2.1 bundle (validated, stored, related) */
        post: operations["upload_bundle_api_v1_insights_stix_bundles_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nhai/alert-explanations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Queue an evidence-grounded explanation of one alert (asynchronous) */
        post: operations["request_alert_explanation_api_v1_nhai_alert_explanations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nhai/asset-summaries": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Queue an evidence-grounded summary of one asset across SIEM, VMS and intelligence (asynchronous) */
        post: operations["request_asset_summary_api_v1_nhai_asset_summaries_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nhai/finding-explanations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Queue an explanation of one VMS finding, with its CVE intelligence and asset (asynchronous) */
        post: operations["request_finding_explanation_api_v1_nhai_finding_explanations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nhai/jobs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** NHAI jobs of the active organization (newest first) */
        get: operations["list_jobs_api_v1_nhai_jobs_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nhai/jobs/{job_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One NHAI job, with its draft result when finished */
        get: operations["get_job_api_v1_nhai_jobs__job_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nhai/jobs/{job_id}/review": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Accept or reject a draft (human review) */
        post: operations["review_job_api_v1_nhai_jobs__job_id__review_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/orgs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Organizations the caller may act on (X-Org-Id values) */
        get: operations["list_orgs_api_v1_orgs_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/platform/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Database, connector and module states */
        get: operations["status_api_v1_platform_status_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/posture/assessment": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Security posture: control areas, compliance, gaps, remediation trend */
        get: operations["assessment_api_v1_posture_assessment_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/posture/overview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Executive overview: posture, incidents, vulnerabilities, SLA, priorities */
        get: operations["overview_api_v1_posture_overview_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/brand/findings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Brand Protection findings */
        get: operations["list_findings_api_v1_protection_brand_findings_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/brand/findings/{finding_id}/case": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Open a case from a brand finding (one case per finding) */
        post: operations["brand_case_api_v1_protection_brand_findings__finding_id__case_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/brand/findings/{finding_id}/indicator": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Add a lookalike domain to Threat Insights (matched against the organization's alerts) */
        post: operations["brand_indicator_api_v1_protection_brand_findings__finding_id__indicator_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/brand/findings/{finding_id}/triage": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Triage a finding */
        post: operations["triage_api_v1_protection_brand_findings__finding_id__triage_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/brand/runs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Monitoring runs (newest first) */
        get: operations["list_runs_api_v1_protection_brand_runs_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/brand/subjects": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Brand Protection watch subjects */
        get: operations["list_subjects_api_v1_protection_brand_subjects_get"];
        put?: never;
        /** Add a watch subject */
        post: operations["add_subject_api_v1_protection_brand_subjects_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/brand/subjects/{subject_id}/runs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Run lookalike monitoring for a domain subject (through the configured resolver) */
        post: operations["run_monitoring_api_v1_protection_brand_subjects__subject_id__runs_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/email/dmarc-reports": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** DMARC aggregate reports (newest first) */
        get: operations["list_dmarc_api_v1_protection_email_dmarc_reports_get"];
        put?: never;
        /** Upload a DMARC aggregate report (XML) */
        post: operations["upload_dmarc_api_v1_protection_email_dmarc_reports_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/email/dmarc-reports/{report_id}/case": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Open a case from a DMARC report with failing messages */
        post: operations["dmarc_case_api_v1_protection_email_dmarc_reports__report_id__case_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/protection/email/domains": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Email domains of the organization */
        get: operations["list_domains_api_v1_protection_email_domains_get"];
        put?: never;
        /** Register an email domain (verification pending) */
        post: operations["add_domain_api_v1_protection_email_domains_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/reports": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Report history of the active organization */
        get: operations["list_reports_api_v1_reports_get"];
        put?: never;
        /** Request a report (idempotent per key) */
        post: operations["request_report_api_v1_reports_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/reports/{report_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One report with its sections and source states */
        get: operations["get_report_api_v1_reports__report_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/reports/{report_id}/download": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Download a report (JSON or CSV) */
        get: operations["download_api_v1_reports__report_id__download_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secops/handovers": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Shift handovers (newest first) */
        get: operations["list_handovers_api_v1_secops_handovers_get"];
        put?: never;
        /** Submit a shift handover (the queue is frozen into it) */
        post: operations["create_handover_api_v1_secops_handovers_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secops/handovers/draft": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The current queue, to start a shift handover */
        get: operations["handover_draft_api_v1_secops_handovers_draft_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secops/handovers/{handover_id}/acknowledge": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Acknowledge a handover (incoming analyst) */
        post: operations["acknowledge_api_v1_secops_handovers__handover_id__acknowledge_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secops/notifications": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The signed-in user's notifications */
        get: operations["notifications_api_v1_secops_notifications_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secops/notifications/read": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Mark all of the user's notifications as read */
        post: operations["mark_read_api_v1_secops_notifications_read_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secops/sla/escalate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Run the SLA escalation check now */
        post: operations["run_escalation_api_v1_secops_sla_escalate_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secops/sla/performance": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Historical SLA performance (cases created in the period) */
        get: operations["sla_performance_api_v1_secops_sla_performance_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secops/sla/policies": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** SLA policies of the organization (one per severity) */
        get: operations["get_policies_api_v1_secops_sla_policies_get"];
        /** Set SLA policies (applies to cases created from now on) */
        put: operations["set_policies_api_v1_secops_sla_policies_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secops/sla/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** SLA state of every open case */
        get: operations["sla_status_api_v1_secops_sla_status_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/service/whoami": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Machine identity check: organization and site come from the credential only */
        get: operations["whoami_api_v1_service_whoami_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sites": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Sites of the active organization */
        get: operations["list_sites_api_v1_sites_get"];
        put?: never;
        /** Create a site in the active organization */
        post: operations["create_site_api_v1_sites_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sites/{site_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One site of the active organization */
        get: operations["get_site_api_v1_sites__site_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/ai-activity": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Every AI analysis, recommendation, failure and review (audit) */
        get: operations["ai_activity_api_v1_soar_ai_activity_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/approvals": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Approvals of the organization (pending first) */
        get: operations["list_approvals_api_v1_soar_approvals_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/approvals/{approval_id}/decision": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Approve or reject (not your own request) */
        post: operations["decide_api_v1_soar_approvals__approval_id__decision_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/emergency-stop": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Turn the emergency stop on or off (always audited) */
        post: operations["emergency_stop_api_v1_soar_emergency_stop_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/operations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** SOAR operations centre: state, limits and the live timeline */
        get: operations["operations_api_v1_soar_operations_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/playbooks": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Playbooks of the organization (latest version of each) */
        get: operations["list_playbooks_api_v1_soar_playbooks_get"];
        put?: never;
        /** Create a playbook, or a new version of one (draft) */
        post: operations["create_playbook_api_v1_soar_playbooks_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/playbooks/{name}/versions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Every version of a playbook */
        get: operations["playbook_versions_api_v1_soar_playbooks__name__versions_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/playbooks/{playbook_id}/retire": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Retire a version (it can no longer run) */
        post: operations["retire_version_api_v1_soar_playbooks__playbook_id__retire_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/playbooks/{playbook_id}/review": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Approve or reject a version (not your own) */
        post: operations["review_version_api_v1_soar_playbooks__playbook_id__review_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/playbooks/{playbook_id}/submit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Submit a validated version for approval */
        post: operations["submit_version_api_v1_soar_playbooks__playbook_id__submit_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/playbooks/{playbook_id}/validate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Validate a draft version */
        post: operations["validate_version_api_v1_soar_playbooks__playbook_id__validate_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/policy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The organization's response authorization policy */
        get: operations["get_policy_api_v1_soar_policy_get"];
        /** Set the organization's response authorization policy */
        put: operations["put_policy_api_v1_soar_policy_put"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/recommendations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Playbooks whose triggers match a case's alerts */
        get: operations["recommendations_api_v1_soar_recommendations_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/runs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Runs of the organization (newest first) */
        get: operations["list_runs_api_v1_soar_runs_get"];
        put?: never;
        /** Run a playbook for a case (dry run by default) */
        post: operations["create_run_api_v1_soar_runs_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/runs/{run_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One run with its steps, approvals and receipts */
        get: operations["get_run_api_v1_soar_runs__run_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soar/steps/{step_id}/dispatch": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Re-send a dispatched step (same request id) */
        post: operations["redispatch_api_v1_soar_steps__step_id__dispatch_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/alerts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Stored alerts of the active organization (newest first) */
        get: operations["list_alerts_api_v1_soc_alerts_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/alerts/{alert_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One stored alert */
        get: operations["get_alert_api_v1_soc_alerts__alert_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/alerts/{alert_id}/assign": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Assign an alert to an analyst (or unassign) */
        post: operations["assign_alert_api_v1_soc_alerts__alert_id__assign_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/alerts/{alert_id}/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The original alert document from its source (read by the API, redacted) */
        get: operations["alert_evidence_api_v1_soc_alerts__alert_id__evidence_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/alerts/{alert_id}/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Triage: change an alert's status */
        post: operations["set_alert_status_api_v1_soc_alerts__alert_id__status_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/cases": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Cases of the active organization (newest first) */
        get: operations["list_cases_api_v1_soc_cases_get"];
        put?: never;
        /** Create a case from stored alerts (deduplicated per source and source id) */
        post: operations["create_case_api_v1_soc_cases_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/cases/{case_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One case with its alerts and timeline */
        get: operations["get_case_api_v1_soc_cases__case_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/cases/{case_id}/assign": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Assign a case to an analyst (or unassign) */
        post: operations["assign_case_api_v1_soc_cases__case_id__assign_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/cases/{case_id}/notes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Add a note to the case timeline */
        post: operations["add_note_api_v1_soc_cases__case_id__notes_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/cases/{case_id}/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change a case's status (closing needs cases:close) */
        post: operations["set_case_status_api_v1_soc_cases__case_id__status_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/soc/ingest/alerts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Forwarder: deliver Wazuh alerts (machine identity) */
        post: operations["ingest_api_v1_soc_ingest_alerts_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/audit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** VMS audit evidence (scopes, scans, findings, remediation, retests) */
        get: operations["vms_audit_api_v1_vms_audit_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/findings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Findings, highest risk first */
        get: operations["list_findings_api_v1_vms_findings_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/findings/{finding_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** One finding: CVE intelligence, remediation, verification, history */
        get: operations["finding_detail_api_v1_vms_findings__finding_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/findings/{finding_id}/retest": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Request a verification scan for one finding (only inside an approved scope, only where scanning is enabled) */
        post: operations["retest_api_v1_vms_findings__finding_id__retest_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/findings/{finding_id}/transition": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Move a finding (manual transitions only) */
        post: operations["transition_api_v1_vms_findings__finding_id__transition_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/remediation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Remediation tasks (overdue first) */
        get: operations["remediation_tasks_api_v1_vms_remediation_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/remediation/{task_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        /** Assign or annotate a remediation task */
        patch: operations["update_task_api_v1_vms_remediation__task_id__patch"];
        trace?: never;
    };
    "/api/v1/vms/report": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Vulnerability report for the organization */
        get: operations["report_api_v1_vms_report_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/risk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Risk prioritization: priorities, KEV, exposure and the riskiest assets */
        get: operations["risk_overview_api_v1_vms_risk_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/scans": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Scan jobs of the organization */
        get: operations["list_scans_api_v1_vms_scans_get"];
        put?: never;
        /** Request a scan inside an approved scope (vms:scan) */
        post: operations["create_scan_api_v1_vms_scans_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/schedules": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Recurring scan schedules */
        get: operations["list_schedules_api_v1_vms_schedules_get"];
        put?: never;
        /** Create a scan schedule inside an approved scope (vms:scope) */
        post: operations["create_schedule_api_v1_vms_schedules_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/schedules/{schedule_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        /** Enable or disable a schedule */
        patch: operations["update_schedule_api_v1_vms_schedules__schedule_id__patch"];
        trace?: never;
    };
    "/api/v1/vms/scopes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Approved scan scopes of the organization */
        get: operations["list_scopes_api_v1_vms_scopes_get"];
        put?: never;
        /** Approve a scan scope (vms:scope) */
        post: operations["create_scope_api_v1_vms_scopes_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/services": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Services and technologies discovered on the organization's assets */
        get: operations["services_api_v1_vms_services_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** VMS readiness for the active organization */
        get: operations["status_api_v1_vms_status_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/worker/claim": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** VMS worker: claim the next scan job of its organization */
        post: operations["claim_api_v1_vms_worker_claim_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/worker/heartbeat": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** VMS worker: report health (machine identity) */
        post: operations["heartbeat_api_v1_vms_worker_heartbeat_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/worker/jobs/{job_id}/finish": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** VMS worker: finish a job (verifies fixed findings) */
        post: operations["finish_api_v1_vms_worker_jobs__job_id__finish_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vms/worker/jobs/{job_id}/results": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** VMS worker: deliver observations (idempotent per batch) */
        post: operations["results_api_v1_vms_worker_jobs__job_id__results_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/healthz": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Liveness (no dependencies) */
        get: operations["healthz_healthz_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/readyz": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Readiness: database reachable and at the expected migration */
        get: operations["readyz_readyz_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
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
            /** Id */
            id?: string | null;
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
            /** Published */
            published?: string | null;
            /**
             * Url
             * @default
             */
            url: string;
        };
        /** AdminOrg */
        AdminOrg: {
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
            /** Slug */
            slug: string;
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "suspended";
        };
        /** AdminOrgCreate */
        AdminOrgCreate: {
            /** Name */
            name: string;
            /** Slug */
            slug: string;
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
            /** Last Login At */
            last_login_at?: string | null;
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
            /** Nhai Job Id */
            nhai_job_id?: string | null;
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
             */
            asset_id?: string | null;
            /** Assignee Id */
            assignee_id?: string | null;
            /** Assignee Label */
            assignee_label?: string | null;
            /**
             * Case Id
             * @description The case this alert is linked to, if any (the most recently linked one when several)
             */
            case_id?: string | null;
            /** External Id */
            external_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
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
            /** Document */
            document?: {
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
            /** Assignee Id */
            assignee_id?: string | null;
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
        /** ApprovalView */
        ApprovalView: {
            action: components["schemas"]["ActionType"];
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            decided_by?: components["schemas"]["ActorRef"] | null;
            /** Decision */
            decision?: ("approve" | "reject") | null;
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
            /** Reason */
            reason?: string | null;
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
        /** AssetAlertRef */
        AssetAlertRef: {
            /** Case Id */
            case_id?: string | null;
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
            /** Fqdn */
            fqdn?: string | null;
            /** Hostname */
            hostname?: string | null;
            /** Ip */
            ip?: string | null;
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
            /** Site Id */
            site_id?: string | null;
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
            /** Cnii */
            cnii?: {
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
            wazuh?: components["schemas"]["WazuhAgentContext"] | null;
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
            /** Port */
            port?: number | null;
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
            /** Last Vms Scan At */
            last_vms_scan_at?: string | null;
            /**
             * State
             * @description monitored: a Wazuh agent AND a VMS scan in 30 days; partial: one of them; unmonitored: neither
             * @enum {string}
             */
            state: "monitored" | "partial" | "unmonitored";
            /** Wazuh Agent Id */
            wazuh_agent_id?: string | null;
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
            /** Fqdn */
            fqdn?: string | null;
            /** Hostname */
            hostname?: string | null;
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
            /** Merged Into */
            merged_into?: string | null;
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
            /** Os Name */
            os_name?: string | null;
            /** Os Platform */
            os_platform?: string | null;
            /** Os Version */
            os_version?: string | null;
            /** Owner */
            owner: string;
            /** Primary Ip */
            primary_ip?: string | null;
            /** Site Id */
            site_id?: string | null;
            /** Site Name */
            site_name?: string | null;
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
            /** Classification */
            classification?: ("server" | "workstation" | "network" | "domain" | "web" | "cloud" | "iot" | "unclassified") | null;
            /** Criticality */
            criticality?: ("low" | "medium" | "high" | "critical") | null;
            /** Display Name */
            display_name?: string | null;
            /** Exposure */
            exposure?: ("internet_facing" | "internal" | "unknown") | null;
            /** Owner */
            owner?: string | null;
            /** Site Id */
            site_id?: string | null;
            /** Tags */
            tags?: string[] | null;
        };
        /**
         * AssignmentRequest
         * @description Assign (or, with null, unassign) an alert or a case. The assignee must be a member of the organization.
         */
        AssignmentRequest: {
            /** Assignee Id */
            assignee_id?: string | null;
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
            /** Total */
            total?: number | null;
        };
        /** BackupRunList */
        BackupRunList: {
            /** Items */
            items: components["schemas"]["BackupRunView"][];
        };
        /** BackupRunView */
        BackupRunView: {
            /** Encrypted */
            encrypted: boolean;
            /** Finished At */
            finished_at?: string | null;
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
            /** Last Drill At */
            last_drill_at?: string | null;
            /** Last Drill Status */
            last_drill_status?: ("succeeded" | "failed") | null;
            /**
             * Note
             * @default
             */
            note: string;
            /** Sha256 */
            sha256?: string | null;
            /** Size Bytes */
            size_bytes?: number | null;
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
            /** Max Assets */
            max_assets?: number | null;
            /** Max Users */
            max_users?: number | null;
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
            /** Max Assets */
            max_assets?: number | null;
            /** Max Users */
            max_users?: number | null;
            /** Name */
            name: string;
            /**
             * Price Minor
             * @description Price in the currency's minor unit (kobo, cents)
             */
            price_minor: number;
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
            /** Url */
            url?: string | null;
            /** Value */
            value: string;
        };
        /** CaseDetail */
        CaseDetail: {
            /** Alert Count */
            alert_count: number;
            /** Alerts */
            alerts: components["schemas"]["StoredAlert"][];
            /** Assignee Id */
            assignee_id?: string | null;
            /** Assignee Label */
            assignee_label?: string | null;
            /** Closed At */
            closed_at?: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** First Response At */
            first_response_at?: string | null;
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
            /** Resolved At */
            resolved_at?: string | null;
            severity: components["schemas"]["Severity"];
            /** Sla Resolution Due At */
            sla_resolution_due_at?: string | null;
            /**
             * Sla Response Due At
             * @description Consolidation: from the SLA policy when the case was created
             */
            sla_response_due_at?: string | null;
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
            /** Assignee Label */
            assignee_label?: string | null;
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
            /** Escalated At */
            escalated_at?: string | null;
            /** First Response At */
            first_response_at?: string | null;
            /** Reference */
            reference: string;
            /** Resolution Due At */
            resolution_due_at?: string | null;
            /**
             * Resolution State
             * @enum {string}
             */
            resolution_state: "met" | "on_track" | "at_risk" | "breached" | "no_policy";
            /** Resolved At */
            resolved_at?: string | null;
            /** Response Due At */
            response_due_at?: string | null;
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
            /** Assignee Id */
            assignee_id?: string | null;
            /** Assignee Label */
            assignee_label?: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** First Response At */
            first_response_at?: string | null;
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
            /** Resolved At */
            resolved_at?: string | null;
            severity: components["schemas"]["Severity"];
            /** Sla Resolution Due At */
            sla_resolution_due_at?: string | null;
            /**
             * Sla Response Due At
             * @description Consolidation: from the SLA policy when the case was created
             */
            sla_response_due_at?: string | null;
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
            /** @description The AI-drafted answer job, when NHAI is configured */
            nhai?: components["schemas"]["NhaiJob"] | null;
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
            /** Document Sha256 */
            document_sha256?: string | null;
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
            /** Document Sha256 */
            document_sha256?: string | null;
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
            /** Revoked At */
            revoked_at?: string | null;
            /** Revoked Reason */
            revoked_reason?: string | null;
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
            /** Latency Ms */
            latency_ms?: number | null;
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
            /** Revoked At */
            revoked_at?: string | null;
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
             */
            scope_org_ids?: string[] | null;
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
             */
            availability_30d?: number | null;
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
            last_check?: components["schemas"]["CniiCheckView"] | null;
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
            /** Last Run At */
            last_run_at?: string | null;
            /** Next Due At */
            next_due_at?: string | null;
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
            /** Site Id */
            site_id?: string | null;
        };
        /** CollectorList */
        CollectorList: {
            /** Items */
            items: components["schemas"]["CollectorView"][];
        };
        /** CollectorUpdate */
        CollectorUpdate: {
            /** Authorization Reference */
            authorization_reference?: string | null;
            /** Enabled */
            enabled?: boolean | null;
            /** Interval Minutes */
            interval_minutes?: number | null;
            /** Settings */
            settings?: {
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
            /** Last Outcome */
            last_outcome?: string | null;
            /** Last Run At */
            last_run_at?: string | null;
            /** Name */
            name: string;
            /**
             * Settings
             * @default {}
             */
            settings: {
                [key: string]: unknown;
            };
            /** Site Id */
            site_id?: string | null;
        };
        /** CompliancePolicyRow */
        CompliancePolicyRow: {
            /** Average Score */
            average_score?: number | null;
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
            /** Checked At */
            checked_at?: string | null;
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
            /** Bound To Asset Id */
            bound_to_asset_id?: string | null;
            /** Bound To Asset Name */
            bound_to_asset_name?: string | null;
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
             */
            checked_at?: string | null;
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
            /** Kev Catalog */
            kev_catalog?: {
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
            /** Cvss V3 */
            cvss_v3?: number | null;
            /** Cvss Vector */
            cvss_vector?: string | null;
            /** Description */
            description: string;
            /** Epss */
            epss?: number | null;
            /** Kev */
            kev: boolean;
            /** Kev Added */
            kev_added?: string | null;
            /**
             * Open Findings
             * @description This organization's open VMS findings that name the CVE
             */
            open_findings: number;
            /** Published */
            published?: string | null;
            /** Snapshots */
            snapshots: number;
            /** Source */
            source: string;
        };
        /** CveRecordIn */
        CveRecordIn: {
            /** Cve Id */
            cve_id: string;
            /** Cvss V3 */
            cvss_v3?: number | null;
            /** Cvss Vector */
            cvss_vector?: string | null;
            /**
             * Description
             * @default
             */
            description: string;
            /** Epss */
            epss?: number | null;
            /**
             * Kev
             * @default false
             */
            kev: boolean;
            /** Kev Added */
            kev_added?: string | null;
            /** Published */
            published?: string | null;
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
            /** Published Policy */
            published_policy?: string | null;
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
            /** Dmarc Policy */
            dmarc_policy?: ("none" | "quarantine" | "reject" | "missing") | null;
            /** Domain */
            domain: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Last Checked At */
            last_checked_at?: string | null;
            /** Spf Valid */
            spf_valid?: boolean | null;
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
            /** Name */
            name?: string | null;
            /** Platform */
            platform?: string | null;
            /**
             * Support
             * @default unknown
             * @enum {string}
             */
            support: "supported" | "unsupported" | "unknown";
            /** Version */
            version?: string | null;
        };
        /** EndpointSummary */
        EndpointSummary: {
            /** Agent Id */
            agent_id: string;
            /** Agent Version */
            agent_version?: string | null;
            /** Groups */
            groups: string[];
            /** Ip */
            ip?: string | null;
            /** Last Keepalive At */
            last_keepalive_at?: string | null;
            /** Name */
            name: string;
            os: components["schemas"]["EndpointOs"];
            /**
             * Status
             * @enum {string}
             */
            status: "active" | "disconnected" | "never_connected" | "pending";
        };
        /** ErrorDetail */
        ErrorDetail: {
            /**
             * Code
             * @description Stable machine-readable code, e.g. forbidden, validation_error
             */
            code: string;
            /** Details */
            details?: unknown | null;
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
         * ExecutionMode
         * @enum {string}
         */
        ExecutionMode: "dry_run" | "live";
        /**
         * ExecutionReceipt
         * @description The Server 1 bridge's signed answer, verified by the engine before it is stored.
         */
        ExecutionReceipt: {
            /** Adapter */
            adapter: string;
            /** Command */
            command?: string | null;
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
        /** FindingCveIntel */
        FindingCveIntel: {
            /**
             * Captured At
             * Format: date-time
             */
            captured_at: string;
            /** Cve Id */
            cve_id: string;
            /** Cvss V3 */
            cvss_v3?: number | null;
            /**
             * Description
             * @default
             */
            description: string;
            /** Epss */
            epss?: number | null;
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
        /** GroupMapping */
        GroupMapping: {
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
            /** Assignee Label */
            assignee_label?: string | null;
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
            /** Assignee Label */
            assignee_label?: string | null;
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
            /** Incoming User Id */
            incoming_user_id?: string | null;
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
            /** Acknowledged At */
            acknowledged_at?: string | null;
            acknowledged_by?: components["schemas"]["ActorRef"] | null;
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
            /** Incoming Label */
            incoming_label?: string | null;
            /** Incoming User Id */
            incoming_user_id?: string | null;
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
            /** Stix Bundle */
            stix_bundle?: {
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
            /** Valid Until */
            valid_until?: string | null;
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
            /** Denominator */
            denominator?: number | null;
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
            /** Numerator */
            numerator?: number | null;
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
            /** Value */
            value?: number | null;
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
        /** ModelRef */
        ModelRef: {
            /** Digest */
            digest?: string | null;
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
            /** Finished At */
            finished_at?: string | null;
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
            /** Outcome */
            outcome?: ("completed" | "source_unconfigured" | "rate_limited" | "failed") | null;
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
            /** Error Code */
            error_code?: string | null;
            /** Finished At */
            finished_at?: string | null;
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
            result?: components["schemas"]["NhaiResult"] | null;
            /** Started At */
            started_at?: string | null;
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
            review?: components["schemas"]["HumanReview"] | null;
            severity_assessment?: components["schemas"]["SeverityAssessment"] | null;
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
            /** Read At */
            read_at?: string | null;
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
             */
            check_id?: string | null;
            /**
             * Cves
             * @default []
             */
            cves: string[];
            /** Cvss V3 */
            cvss_v3?: number | null;
            /** Evidence Ref */
            evidence_ref?: string | null;
            kind: components["schemas"]["ObservationKind"];
            /** Port */
            port?: number | null;
            /** Protocol */
            protocol?: ("tcp" | "udp") | null;
            severity?: components["schemas"]["Severity"] | null;
            target: components["schemas"]["ScopeEntry"];
            /** Title */
            title?: string | null;
        };
        /**
         * ObservationKind
         * @enum {string}
         */
        ObservationKind: "host" | "service" | "technology" | "finding";
        /** OnboardingStatus */
        OnboardingStatus: {
            /** Next Step */
            next_step?: string | null;
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
            /** Last Alert At */
            last_alert_at?: string | null;
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
            /** Plan Code */
            plan_code?: string | null;
            /** Status */
            status: string;
            /** Subscription Status */
            subscription_status?: string | null;
            /** Users */
            users: number;
        };
        /** OrgBillingRow */
        OrgBillingRow: {
            /** Assets */
            assets: number;
            /** Max Assets */
            max_assets?: number | null;
            /** Max Users */
            max_users?: number | null;
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
            /** Plan Code */
            plan_code?: string | null;
            /** Plan Name */
            plan_name?: string | null;
            /** Renews At */
            renews_at?: string | null;
            /** Status */
            status?: string | null;
            /** Users */
            users: number;
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
         * PasswordChangeRequest
         * @description POST /api/v1/auth/password. The new password must differ from the current one; other sessions are revoked.
         */
        PasswordChangeRequest: {
            /** Current Password */
            current_password: string;
            /** New Password */
            new_password: string;
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
            /** Last Drill At */
            last_drill_at?: string | null;
            /** Last Drill Status */
            last_drill_status?: string | null;
            /** Last Succeeded At */
            last_succeeded_at?: string | null;
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
            /** Approved At */
            approved_at?: string | null;
            approved_by?: components["schemas"]["ActorRef"] | null;
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
            validation?: components["schemas"]["PlaybookValidation"] | null;
            /** Version */
            version: number;
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
            /** Score */
            score?: number | null;
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
            /** Unmapped Groups */
            unmapped_groups: string[];
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
            action?: components["schemas"]["ActionType"] | null;
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
            /** Rpo Minutes */
            rpo_minutes?: number | null;
            /** Rto Minutes */
            rto_minutes?: number | null;
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
            /** Last Tested At */
            last_tested_at?: string | null;
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
            /** Rpo Minutes */
            rpo_minutes?: number | null;
            /** Rto Minutes */
            rto_minutes?: number | null;
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
            /** Recovered Point */
            recovered_point?: string | null;
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
            /** Plan Id */
            plan_id?: string | null;
            /** Requested Recovery Point */
            requested_recovery_point?: string | null;
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
            /** Achieved Rpo Minutes */
            achieved_rpo_minutes?: number | null;
            /** Achieved Rto Minutes */
            achieved_rto_minutes?: number | null;
            /** Affected Data */
            affected_data: string;
            /**
             * Backup Reference
             * @default
             */
            backup_reference: string;
            /** Backup Source */
            backup_source?: ("novrsoc_platform_backup" | "external_provider" | "manual_procedure") | null;
            /** Completed At */
            completed_at?: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            decided_by?: components["schemas"]["ActorRef"] | null;
            /** Decision Reason */
            decision_reason?: string | null;
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
            /** Plan Id */
            plan_id?: string | null;
            /** Plan Name */
            plan_name?: string | null;
            /** Recovered Point */
            recovered_point?: string | null;
            requested_by: components["schemas"]["ActorRef"];
            /** Requested Recovery Point */
            requested_recovery_point?: string | null;
            /** Rpo Target Minutes */
            rpo_target_minutes?: number | null;
            /** Rto Target Minutes */
            rto_target_minutes?: number | null;
            /** Started At */
            started_at?: string | null;
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
            /** Assignee Id */
            assignee_id?: string | null;
            /**
             * Note
             * @default
             */
            note: string;
            /** Status */
            status?: ("open" | "in_progress") | null;
        };
        /** RemediationTaskView */
        RemediationTaskView: {
            /** Asset Id */
            asset_id?: string | null;
            /** Assignee Id */
            assignee_id?: string | null;
            /** Assignee Label */
            assignee_label?: string | null;
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
            /** Sha256 */
            sha256?: string | null;
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
            /** Sha256 */
            sha256?: string | null;
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
        /** RetestRequest */
        RetestRequest: {
            /**
             * Note
             * @default
             */
            note: string;
        };
        /** RiskAssetRow */
        RiskAssetRow: {
            /** Asset Id */
            asset_id?: string | null;
            /** Criticality */
            criticality?: string | null;
            /** Exposure */
            exposure?: string | null;
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
            /** Cvss */
            cvss?: number | null;
            /** Epss */
            epss?: number | null;
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
            job?: components["schemas"]["ScanJobClaim"] | null;
            /**
             * Reason
             * @enum {string}
             */
            reason: "job" | "no_job" | "scanning_disabled";
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
            /** Max Runtime Seconds */
            max_runtime_seconds: number;
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
                [key: string]: "completed" | "unreachable" | "refused_out_of_scope" | "failed";
            };
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
             */
            site_id?: string | null;
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
            /** Site Id */
            site_id?: string | null;
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
            /** Last Used At */
            last_used_at?: string | null;
            /** Name */
            name: string;
            /** Revoked At */
            revoked_at?: string | null;
            /** Scopes */
            scopes: string[];
            /** Site Id */
            site_id?: string | null;
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
            kind: "collector" | "vms_worker" | "forwarder" | "email_gateway" | "backup_agent";
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
            /** Agrees With Stored */
            agrees_with_stored?: boolean | null;
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
            /** Median Resolution Minutes */
            median_resolution_minutes?: number | null;
            /** Median Response Minutes */
            median_response_minutes?: number | null;
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
            /** Emergency At */
            emergency_at?: string | null;
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
            /** Updated At */
            updated_at?: string | null;
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
            /** Approval Id */
            approval_id?: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Message */
            message: string;
            receipt?: components["schemas"]["ExecutionReceipt"] | null;
            /** Request Id */
            request_id?: string | null;
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
             */
            asset_id?: string | null;
            /** Assignee Id */
            assignee_id?: string | null;
            /** Assignee Label */
            assignee_label?: string | null;
            /**
             * Case Id
             * @description The case this alert is linked to, if any (the most recently linked one when several)
             */
            case_id?: string | null;
            /** External Id */
            external_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
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
            /** Renews At */
            renews_at?: string | null;
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
            /** Finished At */
            finished_at?: string | null;
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
            /** First Seen */
            first_seen?: string | null;
            /** Last Seen */
            last_seen?: string | null;
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
            /** First Seen */
            first_seen?: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Last Seen */
            last_seen?: string | null;
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
            /** Scan Job Id */
            scan_job_id?: string | null;
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
            remediation?: components["schemas"]["RemediationTaskView"] | null;
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
             */
            asset_id?: string | null;
            /** Asset Name */
            asset_name?: string | null;
            /** Check Id */
            check_id?: string | null;
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
            /** Port */
            port?: number | null;
            /**
             * Priority
             * @enum {string}
             */
            priority: "P1" | "P2" | "P3" | "P4";
            /** Protocol */
            protocol?: string | null;
            /** Remediation Due At */
            remediation_due_at?: string | null;
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
        /** VmsScanView */
        VmsScanView: {
            activity: components["schemas"]["ScanActivity"];
            /** Claimed At */
            claimed_at?: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Error */
            error?: string | null;
            /** Finished At */
            finished_at?: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Outcome
             * @default {}
             */
            outcome: {
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
            /** Last Job Id */
            last_job_id?: string | null;
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
            /** Critical */
            critical?: number | null;
            /** High */
            high?: number | null;
            /** Low */
            low?: number | null;
            /** Medium */
            medium?: number | null;
            source: components["schemas"]["ConnectorState"];
            /**
             * Total
             * @description null when the source is unavailable; never a guessed 0
             */
            total?: number | null;
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
             */
            consent_reference?: string | null;
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
            /** Agent Version */
            agent_version?: string | null;
            /**
             * Groups
             * @default []
             */
            groups: string[];
            /** Last Keepalive At */
            last_keepalive_at?: string | null;
            /** Name */
            name?: string | null;
            sca?: components["schemas"]["ScaSummary"] | null;
            source: components["schemas"]["ConnectorState"];
            /** Status */
            status?: string | null;
            vulnerabilities?: components["schemas"]["VulnerabilitySummary"] | null;
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
            /** Src Ip */
            src_ip?: string | null;
            /**
             * Timestamp
             * Format: date-time
             */
            timestamp: string;
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
export interface operations {
    analytics_api_v1_admin_analytics_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlatformAnalytics"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_backups_api_v1_admin_backups_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BackupRunList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    billing_api_v1_admin_billing_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BillingOverview"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_plan_api_v1_admin_billing_plans_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BillingPlanCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BillingPlanView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    update_plan_api_v1_admin_billing_plans__plan_id__patch: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                plan_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BillingPlanUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BillingPlanView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    set_subscription_api_v1_admin_billing_subscriptions_put: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SubscriptionSet"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BillingOverview"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_exports_api_v1_admin_exports_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DataExportList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_export_api_v1_admin_exports_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DataExportCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DataExportView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    download_export_api_v1_admin_exports__export_id__download_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                export_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": unknown;
                    "text/csv": unknown;
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    revoke_export_api_v1_admin_exports__export_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                export_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DataExportView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    health_api_v1_admin_health_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlatformHealth"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    onboarding_api_v1_admin_onboarding_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OnboardingStatus"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_orgs_api_v1_admin_organizations_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AdminOrgList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_org_api_v1_admin_organizations_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AdminOrgCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AdminOrg"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_identities_api_v1_admin_service_identities_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ServiceIdentityList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    issue_identity_api_v1_admin_service_identities_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ServiceIdentityCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ServiceIdentityIssued"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    revoke_identity_api_v1_admin_service_identities__identity_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                identity_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ServiceIdentityView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_teams_api_v1_admin_teams_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_team_api_v1_admin_teams_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TeamCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    add_member_api_v1_admin_teams__team_id__members_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                team_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TeamMemberAdd"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    remove_member_api_v1_admin_teams__team_id__members__user_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                team_id: string;
                user_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_users_api_v1_admin_users_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AdminUserList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_user_api_v1_admin_users_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AdminUserCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AdminUserCreated"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_memberships_api_v1_admin_users__user_id__memberships_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                user_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MembershipList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    grant_membership_api_v1_admin_users__user_id__memberships_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                user_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["MembershipGrant"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MembershipList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    revoke_membership_api_v1_admin_users__user_id__memberships__org_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                user_id: string;
                org_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MembershipList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    reset_password_api_v1_admin_users__user_id__reset_password_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                user_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AdminUserCreated"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    set_status_api_v1_admin_users__user_id__status_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                user_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["UserStatusUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AdminUser"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    quarantine_api_v1_admin_wazuh_quarantine_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["QuarantineSummary"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_assets_api_v1_assets_get: {
        parameters: {
            query?: {
                q?: string | null;
                kind?: string | null;
                criticality?: ("low" | "medium" | "high" | "critical") | null;
                monitoring?: ("monitored" | "partial" | "unmonitored") | null;
                status?: "active" | "retired" | "all";
                site_id?: string | null;
                limit?: number;
                offset?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AssetList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_asset_api_v1_assets_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AssetCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AssetSummary"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_collectors_api_v1_assets_collectors_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CollectorList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_collector_api_v1_assets_collectors_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CollectorCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CollectorView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    delete_collector_api_v1_assets_collectors__collector_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                collector_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    update_collector_api_v1_assets_collectors__collector_id__patch: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                collector_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CollectorUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CollectorView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    run_collector_api_v1_assets_collectors__collector_id__run_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                collector_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SyncRunView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    conflicts_api_v1_assets_conflicts_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ConflictList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    import_assets_api_v1_assets_import_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AssetCreate"][];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SyncRunView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    sync_runs_api_v1_assets_sync_runs_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SyncRunList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    run_wazuh_sync_api_v1_assets_sync_wazuh_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SyncRunView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    detail_api_v1_assets__asset_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                asset_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AssetDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    update_asset_api_v1_assets__asset_id__patch: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                asset_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AssetUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AssetSummary"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    merge_asset_api_v1_assets__asset_id__merge_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                asset_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AssetMerge"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AssetSummary"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    retire_asset_api_v1_assets__asset_id__retire_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                asset_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AssetRetire"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AssetSummary"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_audit_api_v1_audit_events_get: {
        parameters: {
            query?: {
                limit?: number;
                offset?: number;
                /** @description Action, or a prefix ending in _ */
                action?: string | null;
                outcome?: ("success" | "denied" | "failure") | null;
                actor?: string | null;
                resource_type?: string | null;
                since?: string | null;
                until?: string | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuditEventList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    login_api_v1_auth_login_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["LoginRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["LoginResponse"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    logout_api_v1_auth_logout_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    me_api_v1_auth_me_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SessionInfo"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    change_password_api_v1_auth_password_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PasswordChangeRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    conversations_api_v1_chat_conversations_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChatConversationList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    start_api_v1_chat_conversations_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ChatConversationCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChatConversationView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_conversation_api_v1_chat_conversations__conversation_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                conversation_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChatConversationView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    delete_conversation_api_v1_chat_conversations__conversation_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                conversation_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    ask_api_v1_chat_conversations__conversation_id__messages_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                conversation_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ChatMessageCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChatExchange"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    cnii_access_api_v1_cnii_access_get: {
        parameters: {
            query: {
                sector: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiAccessResponse"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_authorizations_api_v1_cnii_authorizations_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiAuthorizationList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_authorization_api_v1_cnii_authorizations_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CniiAuthorizationCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiAuthorizationView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    revoke_authorization_api_v1_cnii_authorizations__authorization_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CniiAuthorizationRevoke"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiAuthorizationView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    all_designations_api_v1_cnii_designations_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiDesignationList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    grant_api_v1_cnii_designations_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CniiDesignationGrant"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiDesignation"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    mine_api_v1_cnii_designations_mine_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiDesignationList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    revoke_api_v1_cnii_designations__designation_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                designation_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CniiDesignationRevoke"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiDesignation"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_monitored_api_v1_cnii_monitored_assets_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiMonitoredAssetList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    designate_asset_api_v1_cnii_monitored_assets_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CniiMonitoredAssetCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiMonitoredAssetView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    checks_api_v1_cnii_monitored_assets__monitored_id__checks_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                monitored_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiCheckView"][];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    set_schedule_api_v1_cnii_monitored_assets__monitored_id__schedule_put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                monitored_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CniiScheduleSet"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiMonitoredAssetView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    set_monitored_status_api_v1_cnii_monitored_assets__monitored_id__status_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                monitored_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CniiMonitoredAssetStatus"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiMonitoredAssetView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    overview_api_v1_cnii_overview_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiOverview"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    profiles_api_v1_cnii_profiles_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiOrgProfileList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    set_profile_api_v1_cnii_profiles_put: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CniiOrgProfileSet"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiOrgProfile"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    sector_overview_api_v1_cnii_sector_overview_get: {
        parameters: {
            query: {
                sector: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CniiSectorOverview"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    overview_api_v1_continuity_overview_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ContinuityOverview"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_plans_api_v1_continuity_plans_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryPlanList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_plan_api_v1_continuity_plans_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecoveryPlanCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryPlanView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    plan_tested_api_v1_continuity_plans__plan_id__tested_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                plan_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecoveryPlanTested"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryPlanView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_requests_api_v1_continuity_requests_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryRequestList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_request_api_v1_continuity_requests_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecoveryRequestCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryRequestView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_request_api_v1_continuity_requests__request_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                request_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryRequestView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    decide_api_v1_continuity_requests__request_id__decision_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                request_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecoveryDecision"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryRequestView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    progress_api_v1_continuity_requests__request_id__progress_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                request_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecoveryProgress"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryRequestView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    verify_api_v1_continuity_requests__request_id__verify_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                request_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecoveryVerification"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryRequestView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    inventory_api_v1_endpoints_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EndpointInventory"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_mappings_api_v1_endpoints_group_mappings_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GroupMappingList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_mapping_api_v1_endpoints_group_mappings_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["GroupMappingCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GroupMapping"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    delete_mapping_api_v1_endpoints_group_mappings__mapping_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                mapping_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    detail_api_v1_endpoints__agent_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                agent_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EndpointDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_actors_api_v1_insights_actors_get: {
        parameters: {
            query?: {
                q?: string | null;
                attribution?: ("verified" | "suspected" | "unknown") | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ThreatActorList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_actor_api_v1_insights_actors_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ThreatActorCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ThreatActorView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    update_actor_api_v1_insights_actors__actor_id__put: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                actor_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ThreatActorCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ThreatActorView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    link_actor_api_v1_insights_actors__actor_id__links_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                actor_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ActorLinkCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ThreatActorView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    unlink_actor_api_v1_insights_actors__actor_id__links__link_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                actor_id: string;
                link_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ThreatActorView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    correlations_api_v1_insights_correlations_get: {
        parameters: {
            query?: {
                hours?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CorrelationList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_cves_api_v1_insights_cves_get: {
        parameters: {
            query?: {
                kev_only?: boolean;
                q?: string | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CveIntelList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    import_cves_api_v1_insights_cves_import_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CveImport"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CveImportResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    import_cves_from_stix_api_v1_insights_cves_import_stix_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CveImportResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    feed_runs_api_v1_insights_feed_runs_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FeedRunList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_indicators_api_v1_insights_indicators_get: {
        parameters: {
            query?: {
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IndicatorList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    import_indicators_api_v1_insights_indicators_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["IndicatorImport"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IndicatorImportResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    indicator_context_api_v1_insights_indicators__indicator_id__context_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                indicator_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IndicatorContext"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    feeder_ingest_api_v1_insights_ingest_stix_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["StixIngest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StixIngestResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    run_match_api_v1_insights_match_post: {
        parameters: {
            query?: {
                hours?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MatchRunResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_matches_api_v1_insights_matches_get: {
        parameters: {
            query?: {
                alert_id?: string | null;
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InsightMatchList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    set_verdict_api_v1_insights_matches__match_id__verdict_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                match_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["InsightFeedback"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InsightMatchList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_snapshots_api_v1_insights_snapshots_get: {
        parameters: {
            query?: {
                subject?: string | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SnapshotList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_snapshot_api_v1_insights_snapshots_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SnapshotCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SnapshotView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    stix_export_api_v1_insights_stix_get: {
        parameters: {
            query?: {
                kind?: "indicators" | "all";
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    upload_bundle_api_v1_insights_stix_bundles_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["StixIngest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StixIngestResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    request_alert_explanation_api_v1_nhai_alert_explanations_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AlertExplanationRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NhaiJob"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    request_asset_summary_api_v1_nhai_asset_summaries_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AssetSummaryRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NhaiJob"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    request_finding_explanation_api_v1_nhai_finding_explanations_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["FindingExplanationRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NhaiJob"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_jobs_api_v1_nhai_jobs_get: {
        parameters: {
            query?: {
                subject_id?: string | null;
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NhaiJobList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_job_api_v1_nhai_jobs__job_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                job_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NhaiJob"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    review_job_api_v1_nhai_jobs__job_id__review_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                job_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["NhaiReviewRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NhaiJob"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_orgs_api_v1_orgs_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OrgList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    status_api_v1_platform_status_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlatformStatus"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    assessment_api_v1_posture_assessment_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PostureAssessment"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    overview_api_v1_posture_overview_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ExecutiveOverview"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_findings_api_v1_protection_brand_findings_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BrandFindingList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    brand_case_api_v1_protection_brand_findings__finding_id__case_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                finding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CasePromotionResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    brand_indicator_api_v1_protection_brand_findings__finding_id__indicator_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                finding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IndicatorImportResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    triage_api_v1_protection_brand_findings__finding_id__triage_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                finding_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BrandFindingTriage"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BrandFindingView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_runs_api_v1_protection_brand_runs_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MonitoringRunList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_subjects_api_v1_protection_brand_subjects_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WatchSubjectList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    add_subject_api_v1_protection_brand_subjects_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WatchSubjectCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WatchSubject"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    run_monitoring_api_v1_protection_brand_subjects__subject_id__runs_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                subject_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MonitoringRun"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_dmarc_api_v1_protection_email_dmarc_reports_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DmarcReportList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    upload_dmarc_api_v1_protection_email_dmarc_reports_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DmarcUpload"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DmarcReportView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    dmarc_case_api_v1_protection_email_dmarc_reports__report_id__case_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                report_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CasePromotionResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_domains_api_v1_protection_email_domains_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EmailDomainList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    add_domain_api_v1_protection_email_domains_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["EmailDomainCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EmailDomain"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_reports_api_v1_reports_get: {
        parameters: {
            query?: {
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReportList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    request_report_api_v1_reports_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ReportRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReportDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_report_api_v1_reports__report_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                report_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReportDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    download_api_v1_reports__report_id__download_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                report_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": unknown;
                    "text/csv": unknown;
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_handovers_api_v1_secops_handovers_get: {
        parameters: {
            query?: {
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HandoverList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_handover_api_v1_secops_handovers_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["HandoverCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HandoverView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    handover_draft_api_v1_secops_handovers_draft_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HandoverDraft"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    acknowledge_api_v1_secops_handovers__handover_id__acknowledge_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                handover_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["HandoverAcknowledge"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HandoverView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    notifications_api_v1_secops_notifications_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NotificationList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    mark_read_api_v1_secops_notifications_read_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NotificationList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    run_escalation_api_v1_secops_sla_escalate_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EscalationResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    sla_performance_api_v1_secops_sla_performance_get: {
        parameters: {
            query?: {
                days?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SlaPerformance"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_policies_api_v1_secops_sla_policies_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SlaPolicyList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    set_policies_api_v1_secops_sla_policies_put: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SlaPolicySet"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SlaPolicyList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    sla_status_api_v1_secops_sla_status_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SlaStatus"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    whoami_api_v1_service_whoami_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ServiceWhoAmI"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_sites_api_v1_sites_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SiteList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_site_api_v1_sites_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SiteCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Site"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_site_api_v1_sites__site_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                site_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Site"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    ai_activity_api_v1_soar_ai_activity_get: {
        parameters: {
            query?: {
                kind?: string | null;
                module?: string | null;
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AiActivityList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_approvals_api_v1_soar_approvals_get: {
        parameters: {
            query?: {
                pending?: boolean;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ApprovalList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    decide_api_v1_soar_approvals__approval_id__decision_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                approval_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ApprovalDecisionRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RunView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    emergency_stop_api_v1_soar_emergency_stop_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["EmergencyStopRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SoarPolicyView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    operations_api_v1_soar_operations_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SoarOperations"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_playbooks_api_v1_soar_playbooks_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlaybookList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_playbook_api_v1_soar_playbooks_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PlaybookCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlaybookView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    playbook_versions_api_v1_soar_playbooks__name__versions_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                name: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlaybookVersionList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    retire_version_api_v1_soar_playbooks__playbook_id__retire_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                playbook_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlaybookView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    review_version_api_v1_soar_playbooks__playbook_id__review_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                playbook_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PlaybookReview"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlaybookView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    submit_version_api_v1_soar_playbooks__playbook_id__submit_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                playbook_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlaybookView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    validate_version_api_v1_soar_playbooks__playbook_id__validate_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                playbook_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlaybookView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_policy_api_v1_soar_policy_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SoarPolicyView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    put_policy_api_v1_soar_policy_put: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SoarPolicyUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SoarPolicyView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    recommendations_api_v1_soar_recommendations_get: {
        parameters: {
            query: {
                case_id: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecommendationList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_runs_api_v1_soar_runs_get: {
        parameters: {
            query?: {
                case_id?: string | null;
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RunList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_run_api_v1_soar_runs_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RunCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RunView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_run_api_v1_soar_runs__run_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RunView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    redispatch_api_v1_soar_steps__step_id__dispatch_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                step_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RunView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_alerts_api_v1_soc_alerts_get: {
        parameters: {
            query?: {
                status?: ("new" | "acknowledged" | "in_progress" | "closed") | null;
                severity?: ("low" | "medium" | "high" | "critical") | null;
                limit?: number;
                offset?: number;
                q?: string | null;
                assigned?: ("me" | "unassigned") | null;
                asset_id?: string | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AlertList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_alert_api_v1_soc_alerts__alert_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                alert_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AlertDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    assign_alert_api_v1_soc_alerts__alert_id__assign_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                alert_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AssignmentRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AlertDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    alert_evidence_api_v1_soc_alerts__alert_id__evidence_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                alert_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AlertEvidence"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    set_alert_status_api_v1_soc_alerts__alert_id__status_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                alert_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AlertStatusUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AlertDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_cases_api_v1_soc_cases_get: {
        parameters: {
            query?: {
                status?: ("open" | "in_progress" | "resolved" | "closed") | null;
                limit?: number;
                offset?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_case_api_v1_soc_cases_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AlertToCasePromotion"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CasePromotionResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    get_case_api_v1_soc_cases__case_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    assign_case_api_v1_soc_cases__case_id__assign_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AssignmentRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    add_note_api_v1_soc_cases__case_id__notes_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CaseNoteCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    set_case_status_api_v1_soc_cases__case_id__status_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CaseStatusUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CaseDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    ingest_api_v1_soc_ingest_alerts_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AlertIngestBatch"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AlertIngestResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    vms_audit_api_v1_vms_audit_get: {
        parameters: {
            query?: {
                limit?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuditEventList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_findings_api_v1_vms_findings_get: {
        parameters: {
            query?: {
                status?: string | null;
                limit?: number;
                severity?: string | null;
                priority?: string | null;
                asset_id?: string | null;
                q?: string | null;
                open_only?: boolean;
                offset?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsFindingList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    finding_detail_api_v1_vms_findings__finding_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                finding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsFindingDetail"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    retest_api_v1_vms_findings__finding_id__retest_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                finding_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RetestRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VerificationRequestView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    transition_api_v1_vms_findings__finding_id__transition_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                finding_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["FindingTransition"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsFindingView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    remediation_tasks_api_v1_vms_remediation_get: {
        parameters: {
            query?: {
                status?: string | null;
                assigned?: string | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RemediationTaskList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    update_task_api_v1_vms_remediation__task_id__patch: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                task_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RemediationTaskUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RemediationTaskView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    report_api_v1_vms_report_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsReport"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    risk_overview_api_v1_vms_risk_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsRiskOverview"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_scans_api_v1_vms_scans_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsScanList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_scan_api_v1_vms_scans_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VmsScanCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsScanView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_schedules_api_v1_vms_schedules_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsScheduleList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_schedule_api_v1_vms_schedules_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VmsScheduleCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsScheduleView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    update_schedule_api_v1_vms_schedules__schedule_id__patch: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                schedule_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VmsScheduleUpdate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsScheduleView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    list_scopes_api_v1_vms_scopes_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsScopeList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    create_scope_api_v1_vms_scopes_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VmsScopeCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsScopeView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    services_api_v1_vms_services_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ServiceList"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    status_api_v1_vms_status_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsStatus"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    claim_api_v1_vms_worker_claim_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScanClaimResult"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    heartbeat_api_v1_vms_worker_heartbeat_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ComponentHeartbeat"];
            };
        };
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    finish_api_v1_vms_worker_jobs__job_id__finish_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                job_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WorkerFinish"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsScanView"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    results_api_v1_vms_worker_jobs__job_id__results_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                job_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ScanResultBatch"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VmsResultAck"];
                };
            };
            /** @description Bad request */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Forbidden (permission, organization or CSRF) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Not found (also returned for another organization's record) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
            /** @description Validation error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    healthz_healthz_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
        };
    };
    readyz_readyz_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReadinessResponse"];
                };
            };
            /** @description Service Unavailable */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReadinessResponse"];
                };
            };
        };
    };
}
