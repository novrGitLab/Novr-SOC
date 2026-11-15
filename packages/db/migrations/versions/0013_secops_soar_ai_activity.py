"""Security operations: SLA policies and case SLA tracking, alert and case assignment, shift handovers, notifications,
the playbook approval lifecycle, SOAR emergency stop and execution limits, and the AI activity record.

sla_policies        one active policy per (organization, severity): response and resolution targets, escalation
cases               SLA due times are copied from the policy when the case is created (sla_policy_snapshot keeps the
                    targets that applied), first_response_at, resolved_at, escalated_at
shift_handovers     an analyst's shift summary with a frozen snapshot of the queue; acknowledged by another person
notifications       per-user notifications inside one organization (RLS: own rows only)
soar_playbooks      lifecycle draft -> validated -> pending_approval -> approved -> retired; approval by someone other
                    than the author (CHECK). Only an approved, enabled version can run. Existing versions return to
                    draft: they were never approved under this lifecycle.
soar_policies       emergency stop (blocks new runs and every dispatch), runs per hour, dispatch attempts
ai_activity         every AI action (explanation requested/completed/failed, recommendation, proposed action, review,
                    chat question/answer), append-only even for the schema owner. AI analysis is recorded here; response
                    execution stays in soar_steps and the audit log. The two are never the same record.

Revision ID: 0013_secops_soar_ai_activity
Revises: 0012_asset_inventory
"""
from alembic import op

revision = "0013_secops_soar_ai_activity"
down_revision = "0012_asset_inventory"
branch_labels = None
depends_on = None

TENANT = ["sla_policies", "shift_handovers", "ai_activity"]


def upgrade() -> None:
    op.execute("""
    CREATE TABLE novrsoc.sla_policies (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
      response_minutes integer NOT NULL CHECK (response_minutes BETWEEN 1 AND 43200),
      resolution_minutes integer NOT NULL CHECK (resolution_minutes BETWEEN 1 AND 525600),
      escalate_before_minutes integer NOT NULL DEFAULT 0 CHECK (escalate_before_minutes BETWEEN 0 AND 10080),
      escalate_to_role text NOT NULL DEFAULT 'soc_manager' CHECK (escalate_to_role IN ('soc_manager', 'super_admin')),
      updated_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, severity),
      CHECK (resolution_minutes >= response_minutes));
    ALTER TABLE novrsoc.cases
      ADD COLUMN sla_response_due_at timestamptz,
      ADD COLUMN sla_resolution_due_at timestamptz,
      ADD COLUMN sla_policy_snapshot jsonb,
      ADD COLUMN first_response_at timestamptz,
      ADD COLUMN resolved_at timestamptz,
      ADD COLUMN escalated_at timestamptz;
    ALTER TABLE novrsoc.alerts ADD COLUMN assignee_id uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL;
    ALTER TABLE novrsoc.case_events DROP CONSTRAINT case_events_kind_check;
    ALTER TABLE novrsoc.case_events ADD CONSTRAINT case_events_kind_check CHECK (kind IN ('created', 'note', 'status_changed',
      'alert_linked', 'assigned', 'remediation', 'evidence', 'sla_escalated', 'closure', 'severity_changed'));

    CREATE TABLE novrsoc.shift_handovers (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      author_id uuid NOT NULL REFERENCES novrsoc.users(id),
      author_label text NOT NULL DEFAULT '',
      shift_start timestamptz NOT NULL, shift_end timestamptz NOT NULL,
      summary text NOT NULL CHECK (length(summary) BETWEEN 10 AND 8000),
      watch_items jsonb NOT NULL DEFAULT '[]'::jsonb,
      snapshot jsonb NOT NULL,
      incoming_user_id uuid REFERENCES novrsoc.users(id),
      status text NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'acknowledged')),
      acknowledged_by uuid REFERENCES novrsoc.users(id), acknowledged_label text, acknowledged_at timestamptz,
      acknowledgement_note text NOT NULL DEFAULT '' CHECK (length(acknowledgement_note) <= 2000),
      created_at timestamptz NOT NULL DEFAULT now(),
      CHECK (shift_end > shift_start),
      CHECK (acknowledged_by IS NULL OR acknowledged_by <> author_id),
      CHECK ((status = 'acknowledged') = (acknowledged_at IS NOT NULL)));
    CREATE INDEX shift_handovers_org ON novrsoc.shift_handovers (org_id, created_at DESC);

    CREATE TABLE novrsoc.notifications (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      user_id uuid NOT NULL REFERENCES novrsoc.users(id) ON DELETE CASCADE,
      kind text NOT NULL CHECK (kind ~ '^[a-z_]{3,40}$'),
      title text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
      body text NOT NULL DEFAULT '' CHECK (length(body) <= 2000),
      link text NOT NULL DEFAULT '' CHECK (link = '' OR link ~ '^/app(/[A-Za-z0-9._~%-]+)*/?(\\?[A-Za-z0-9=&._%-]*)?$'),
      created_at timestamptz NOT NULL DEFAULT now(),
      read_at timestamptz);
    CREATE INDEX notifications_user ON novrsoc.notifications (user_id, created_at DESC);
    ALTER TABLE novrsoc.notifications ENABLE ROW LEVEL SECURITY;
    CREATE POLICY notifications_own ON novrsoc.notifications FOR SELECT USING (org_id = novrsoc.app_org() AND user_id = novrsoc.app_user());
    CREATE POLICY notifications_own_update ON novrsoc.notifications FOR UPDATE
      USING (org_id = novrsoc.app_org() AND user_id = novrsoc.app_user()) WITH CHECK (org_id = novrsoc.app_org() AND user_id = novrsoc.app_user());
    CREATE POLICY notifications_insert ON novrsoc.notifications FOR INSERT WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT, UPDATE ON novrsoc.notifications TO novrsoc_app;

    ALTER TABLE novrsoc.soar_playbooks
      ADD COLUMN status text NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'validated', 'pending_approval', 'approved', 'retired')),
      ADD COLUMN description text NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
      ADD COLUMN execution_policy jsonb NOT NULL DEFAULT '{"modes": ["dry_run"], "min_case_severity": "low", "max_runs_per_day": 20}'::jsonb,
      ADD COLUMN validation jsonb NOT NULL DEFAULT '{}'::jsonb,
      ADD COLUMN submitted_at timestamptz,
      ADD COLUMN approved_by uuid REFERENCES novrsoc.users(id),
      ADD COLUMN approved_label text,
      ADD COLUMN approved_at timestamptz,
      ADD COLUMN review_note text NOT NULL DEFAULT '',
      ADD COLUMN retired_at timestamptz;
    ALTER TABLE novrsoc.soar_playbooks ADD CONSTRAINT soar_playbooks_no_self_approval
      CHECK (approved_by IS NULL OR created_by IS NULL OR approved_by <> created_by);
    ALTER TABLE novrsoc.soar_playbooks ADD CONSTRAINT soar_playbooks_approved_has_approver
      CHECK (status <> 'approved' OR approved_by IS NOT NULL);
    ALTER TABLE novrsoc.soar_policies
      ADD COLUMN emergency_stop boolean NOT NULL DEFAULT false,
      ADD COLUMN emergency_reason text NOT NULL DEFAULT '',
      ADD COLUMN emergency_by uuid REFERENCES novrsoc.users(id),
      ADD COLUMN emergency_at timestamptz,
      ADD COLUMN max_runs_per_hour integer NOT NULL DEFAULT 20 CHECK (max_runs_per_hour BETWEEN 1 AND 500),
      ADD COLUMN max_dispatch_attempts integer NOT NULL DEFAULT 3 CHECK (max_dispatch_attempts BETWEEN 1 AND 10);
    ALTER TABLE novrsoc.soar_steps ADD COLUMN dispatch_attempts integer NOT NULL DEFAULT 0;
    -- NHAI serves VMS finding explanations, asset summaries and NovrChat answers through the same worker
    ALTER TABLE novrsoc.nhai_jobs DROP CONSTRAINT nhai_jobs_task_check;
    ALTER TABLE novrsoc.nhai_jobs ADD CONSTRAINT nhai_jobs_task_check CHECK (task IN ('alert_explanation', 'behavioural_insight_summary',
      'investigation_assistance', 'case_note_draft', 'finding_explanation', 'asset_summary', 'chat_answer'));

    CREATE TABLE novrsoc.ai_activity (
      id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      occurred_at timestamptz NOT NULL DEFAULT now(),
      kind text NOT NULL CHECK (kind IN ('analysis_requested', 'analysis_completed', 'analysis_failed', 'recommendation',
                                         'proposed_action', 'review', 'chat_question', 'chat_answer', 'chat_refused')),
      module text NOT NULL CHECK (module ~ '^[a-z_]{2,40}$'),
      task text NOT NULL DEFAULT '',
      subject_type text NOT NULL DEFAULT '', subject_id text NOT NULL DEFAULT '',
      actor_type text NOT NULL CHECK (actor_type IN ('user', 'system')),
      actor_id uuid, actor_label text NOT NULL DEFAULT '',
      model text NOT NULL DEFAULT '',
      outcome text NOT NULL CHECK (outcome IN ('success', 'failure', 'pending', 'refused')),
      summary text NOT NULL DEFAULT '' CHECK (length(summary) <= 500),
      details jsonb NOT NULL DEFAULT '{}'::jsonb,
      nhai_job_id uuid);
    CREATE INDEX ai_activity_org_time ON novrsoc.ai_activity (org_id, occurred_at DESC);
    CREATE FUNCTION novrsoc.ai_activity_immutable() RETURNS trigger LANGUAGE plpgsql AS
      $$ BEGIN RAISE EXCEPTION 'ai_activity is append-only'; END $$;
    CREATE TRIGGER ai_activity_no_update BEFORE UPDATE OR DELETE ON novrsoc.ai_activity
      FOR EACH ROW EXECUTE FUNCTION novrsoc.ai_activity_immutable();
    CREATE TRIGGER ai_activity_no_truncate BEFORE TRUNCATE ON novrsoc.ai_activity
      FOR EACH STATEMENT EXECUTE FUNCTION novrsoc.ai_activity_immutable();
    """)
    for t in TENANT:
        op.execute(f"""
        ALTER TABLE novrsoc.{t} ENABLE ROW LEVEL SECURITY;
        CREATE POLICY {t}_tenant ON novrsoc.{t} FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());""")
    op.execute("""
    GRANT SELECT, INSERT, UPDATE ON novrsoc.sla_policies, novrsoc.shift_handovers TO novrsoc_app;
    GRANT SELECT, INSERT ON novrsoc.ai_activity TO novrsoc_app;
    -- the background jobs worker lists the organizations it maintains (no tenant data)
    CREATE FUNCTION novrsoc.jobs_org_ids() RETURNS SETOF uuid
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ SELECT id FROM novrsoc.organizations WHERE status = 'active' ORDER BY id $$;
    REVOKE ALL ON FUNCTION novrsoc.jobs_org_ids() FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.jobs_org_ids() TO novrsoc_app;
    -- users of the active organization holding a role (escalation and handover recipients); ids and labels only
    CREATE FUNCTION novrsoc.org_users_with_role(p_roles text[]) RETURNS TABLE (user_id uuid, email citext, role_key text)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ SELECT u.id, u.email, m.role_key FROM novrsoc.memberships m JOIN novrsoc.users u ON u.id = m.user_id
          WHERE m.org_id = novrsoc.app_org() AND u.status = 'active' AND m.role_key = ANY(p_roles) ORDER BY u.email $$;
    REVOKE ALL ON FUNCTION novrsoc.org_users_with_role(text[]) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.org_users_with_role(text[]) TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP FUNCTION IF EXISTS novrsoc.org_users_with_role(text[]);
    DROP FUNCTION IF EXISTS novrsoc.jobs_org_ids();
    DROP TABLE IF EXISTS novrsoc.ai_activity;
    DROP FUNCTION IF EXISTS novrsoc.ai_activity_immutable();
    DELETE FROM novrsoc.nhai_jobs WHERE task IN ('finding_explanation', 'asset_summary', 'chat_answer');
    ALTER TABLE novrsoc.nhai_jobs DROP CONSTRAINT nhai_jobs_task_check;
    ALTER TABLE novrsoc.nhai_jobs ADD CONSTRAINT nhai_jobs_task_check CHECK (task IN ('alert_explanation', 'behavioural_insight_summary',
      'investigation_assistance', 'case_note_draft'));
    ALTER TABLE novrsoc.soar_steps DROP COLUMN IF EXISTS dispatch_attempts;
    ALTER TABLE novrsoc.soar_policies DROP COLUMN IF EXISTS emergency_stop, DROP COLUMN IF EXISTS emergency_reason,
      DROP COLUMN IF EXISTS emergency_by, DROP COLUMN IF EXISTS emergency_at, DROP COLUMN IF EXISTS max_runs_per_hour,
      DROP COLUMN IF EXISTS max_dispatch_attempts;
    ALTER TABLE novrsoc.soar_playbooks DROP CONSTRAINT IF EXISTS soar_playbooks_approved_has_approver;
    ALTER TABLE novrsoc.soar_playbooks DROP CONSTRAINT IF EXISTS soar_playbooks_no_self_approval;
    ALTER TABLE novrsoc.soar_playbooks DROP COLUMN IF EXISTS status, DROP COLUMN IF EXISTS description,
      DROP COLUMN IF EXISTS execution_policy, DROP COLUMN IF EXISTS validation, DROP COLUMN IF EXISTS submitted_at,
      DROP COLUMN IF EXISTS approved_by, DROP COLUMN IF EXISTS approved_label, DROP COLUMN IF EXISTS approved_at,
      DROP COLUMN IF EXISTS review_note, DROP COLUMN IF EXISTS retired_at;
    DROP TABLE IF EXISTS novrsoc.notifications, novrsoc.shift_handovers;
    DELETE FROM novrsoc.case_events WHERE kind NOT IN ('created', 'note', 'status_changed', 'alert_linked');
    ALTER TABLE novrsoc.case_events DROP CONSTRAINT case_events_kind_check;
    ALTER TABLE novrsoc.case_events ADD CONSTRAINT case_events_kind_check CHECK (kind IN ('created', 'note', 'status_changed', 'alert_linked'));
    ALTER TABLE novrsoc.alerts DROP COLUMN IF EXISTS assignee_id;
    ALTER TABLE novrsoc.cases DROP COLUMN IF EXISTS sla_response_due_at, DROP COLUMN IF EXISTS sla_resolution_due_at,
      DROP COLUMN IF EXISTS sla_policy_snapshot, DROP COLUMN IF EXISTS first_response_at, DROP COLUMN IF EXISTS resolved_at,
      DROP COLUMN IF EXISTS escalated_at;
    DROP TABLE IF EXISTS novrsoc.sla_policies;
    """)
