"""NovrSOAR policy-driven orchestration (automatic, pre-authorized response) and the exact bridge request of each step.

  * soar_policies: the organization's automation policy. Off by default.
      automation_enabled, case_creation (+ case_min_severity), auto_actions (pre-authorized consequential actions,
      always a subset of allowed_actions), auto_min_confidence, auto_max_dispatch_per_hour, protected_targets (IPs,
      CIDRs, agent ids, accounts no response may ever target), automation_since and the (received_at, id) cursor of the
      last alert considered. Switching automation on sets automation_since and the cursor to now: alerts received
      before that are never acted on.
  * soar_runs: origin (manual | automatic), confidence and trigger_alert_id. requested_by may be NULL only for an
    automatic run (CHECK): every manual run still names its human requester.
  * soar_approvals: auth_kind (human | policy). A policy authorization is an approved record with no human decider,
    written by the engine when the pre-authorization policy allowed the step. A human approval keeps the existing rule
    (decider differs from requester); its requester is a person, or the automation for an automatic run (CHECK).
  * soar_steps.request: the exact canonical request body signed and sent to the bridge (no secret is part of it).
  * soar_automation_events: one row per decision taken for a new alert (and playbook). UNIQUE (org, alert, playbook)
    makes the automation idempotent across workers and retries.
  * alerts (org_id, received_at, id): the automation cursor's index.

Downgrade removes automatic runs (and their steps and approvals) before restoring NOT NULL; the audit log keeps them.

Revision ID: 0020_soar_automation
Revises: 0019_org_portals_onboarding
"""
from alembic import op

revision = "0020_soar_automation"
down_revision = "0019_org_portals_onboarding"
branch_labels = None
depends_on = None

DECISIONS = ("('case_created', 'case_joined', 'run_started', 'skipped_emergency_stop', 'skipped_limit', 'skipped_severity', "
             "'failed')")


def upgrade() -> None:
    op.execute(f"""
    ALTER TABLE novrsoc.soar_policies
      ADD COLUMN automation_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN case_creation boolean NOT NULL DEFAULT false,
      ADD COLUMN case_min_severity text NOT NULL DEFAULT 'high' CHECK (case_min_severity IN ('low', 'medium', 'high', 'critical')),
      ADD COLUMN auto_actions text[] NOT NULL DEFAULT '{{}}',
      ADD COLUMN auto_min_confidence integer NOT NULL DEFAULT 80 CHECK (auto_min_confidence BETWEEN 0 AND 100),
      ADD COLUMN auto_max_dispatch_per_hour integer NOT NULL DEFAULT 20 CHECK (auto_max_dispatch_per_hour BETWEEN 1 AND 500),
      ADD COLUMN protected_targets text[] NOT NULL DEFAULT '{{}}',
      ADD COLUMN automation_since timestamptz,
      ADD COLUMN automation_cursor_at timestamptz,
      ADD COLUMN automation_cursor_id uuid,
      ADD CONSTRAINT soar_policies_auto_subset CHECK (auto_actions <@ allowed_actions);

    ALTER TABLE novrsoc.soar_runs
      ADD COLUMN origin text NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual', 'automatic')),
      ADD COLUMN confidence integer CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 100),
      ADD COLUMN trigger_alert_id uuid,
      ALTER COLUMN requested_by DROP NOT NULL,
      ADD CONSTRAINT soar_runs_manual_has_requester CHECK (origin = 'automatic' OR requested_by IS NOT NULL);

    ALTER TABLE novrsoc.soar_approvals
      ADD COLUMN auth_kind text NOT NULL DEFAULT 'human' CHECK (auth_kind IN ('human', 'policy')),
      ALTER COLUMN requested_by DROP NOT NULL,
      ADD CONSTRAINT soar_approvals_policy_shape CHECK (auth_kind = 'human' OR (decision = 'approve' AND decided_by IS NULL)),
      ADD CONSTRAINT soar_approvals_requester CHECK (requested_by IS NOT NULL OR requested_label = 'NovrSOAR automation');

    ALTER TABLE novrsoc.soar_steps ADD COLUMN request jsonb;

    CREATE TABLE novrsoc.soar_automation_events (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id        uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      alert_id      uuid NOT NULL,
      playbook_name text NOT NULL DEFAULT '',
      decision      text NOT NULL CHECK (decision IN {DECISIONS}),
      confidence    integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
      factors       text[] NOT NULL DEFAULT '{{}}',
      case_id       uuid,
      run_id        uuid,
      detail        text NOT NULL DEFAULT '' CHECK (length(detail) <= 500),
      created_at    timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, alert_id, playbook_name),
      FOREIGN KEY (alert_id, org_id) REFERENCES novrsoc.alerts (id, org_id) ON DELETE CASCADE);
    CREATE INDEX soar_automation_events_recent ON novrsoc.soar_automation_events (org_id, created_at DESC);
    ALTER TABLE novrsoc.soar_automation_events ENABLE ROW LEVEL SECURITY;
    CREATE POLICY soar_automation_events_tenant ON novrsoc.soar_automation_events FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT ON novrsoc.soar_automation_events TO novrsoc_app;
    GRANT UPDATE (run_id) ON novrsoc.soar_automation_events TO novrsoc_app;

    CREATE INDEX IF NOT EXISTS alerts_received_cursor ON novrsoc.alerts (org_id, received_at, id);
    """)


def downgrade() -> None:
    op.execute("""
    DROP INDEX IF EXISTS novrsoc.alerts_received_cursor;
    DROP TABLE IF EXISTS novrsoc.soar_automation_events;
    ALTER TABLE novrsoc.soar_steps DROP COLUMN IF EXISTS request;
    DELETE FROM novrsoc.soar_runs WHERE origin = 'automatic';
    DELETE FROM novrsoc.soar_approvals WHERE requested_by IS NULL;
    ALTER TABLE novrsoc.soar_approvals DROP CONSTRAINT IF EXISTS soar_approvals_policy_shape,
      DROP CONSTRAINT IF EXISTS soar_approvals_requester, DROP COLUMN IF EXISTS auth_kind, ALTER COLUMN requested_by SET NOT NULL;
    ALTER TABLE novrsoc.soar_runs DROP CONSTRAINT IF EXISTS soar_runs_manual_has_requester,
      DROP COLUMN IF EXISTS trigger_alert_id, DROP COLUMN IF EXISTS confidence, DROP COLUMN IF EXISTS origin,
      ALTER COLUMN requested_by SET NOT NULL;
    ALTER TABLE novrsoc.soar_policies DROP CONSTRAINT IF EXISTS soar_policies_auto_subset,
      DROP COLUMN IF EXISTS automation_cursor_id, DROP COLUMN IF EXISTS automation_cursor_at, DROP COLUMN IF EXISTS automation_since,
      DROP COLUMN IF EXISTS protected_targets, DROP COLUMN IF EXISTS auto_max_dispatch_per_hour,
      DROP COLUMN IF EXISTS auto_min_confidence, DROP COLUMN IF EXISTS auto_actions, DROP COLUMN IF EXISTS case_min_severity,
      DROP COLUMN IF EXISTS case_creation, DROP COLUMN IF EXISTS automation_enabled;
    """)
