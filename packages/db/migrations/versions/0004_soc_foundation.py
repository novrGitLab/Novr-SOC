"""SOC foundation: stored alerts, ingest quarantine, cases, case-alert links and the case timeline.

  * alerts are organisation-owned; dedupe on (org_id, source, external_id); raw capped by the API (32 KB).
  * alert_quarantine holds alerts no organisation could be determined for. It has NO organisation, is readable
    only by platform administrators, and is written only through novrsoc.quarantine_alert().
  * cases dedupe on (org_id, source, source_id), so promoting the same alert twice returns the same case.
  * case_alerts / case_events reference cases and alerts through (id, org_id) composite keys, so a case can
    never link or log another organisation's records.
  * case_events is append-only for the API role (no UPDATE/DELETE grant).
No automatic containment exists anywhere in this schema.

Revision ID: 0004_soc_foundation
Revises: 0003_endpoint_foundation
"""
from alembic import op

revision = "0004_soc_foundation"
down_revision = "0003_endpoint_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE novrsoc.alerts (
      id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id           uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      source           text NOT NULL CHECK (source IN ('wazuh', 'local_fixture')),
      external_id      text NOT NULL CHECK (length(external_id) BETWEEN 1 AND 200),
      rule_id          text NOT NULL DEFAULT '',
      rule_level       integer NOT NULL CHECK (rule_level BETWEEN 0 AND 16),
      rule_description text NOT NULL DEFAULT '' CHECK (length(rule_description) <= 1000),
      severity         text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
      agent_id         text NOT NULL DEFAULT '',
      agent_name       text NOT NULL DEFAULT '',
      agent_groups     text[] NOT NULL DEFAULT '{}',
      src_ip           inet,
      mitre_techniques text[] NOT NULL DEFAULT '{}',
      observed_at      timestamptz NOT NULL,
      received_at      timestamptz NOT NULL DEFAULT now(),
      status           text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'in_progress', 'closed')),
      status_reason    text NOT NULL DEFAULT '',
      updated_at       timestamptz NOT NULL DEFAULT now(),
      raw              jsonb NOT NULL DEFAULT '{}'::jsonb,
      UNIQUE (org_id, source, external_id),
      UNIQUE (id, org_id)
    );
    CREATE INDEX alerts_org_observed ON novrsoc.alerts (org_id, observed_at DESC);

    CREATE TABLE novrsoc.alert_quarantine (
      id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      received_at  timestamptz NOT NULL DEFAULT now(),
      source       text NOT NULL,
      external_id  text NOT NULL,
      reason       text NOT NULL CHECK (reason IN ('no_organization_for_groups', 'ambiguous_organization')),
      agent_groups text[] NOT NULL DEFAULT '{}',
      raw          jsonb NOT NULL DEFAULT '{}'::jsonb,
      UNIQUE (source, external_id)
    );

    CREATE SEQUENCE novrsoc.case_number_seq;
    CREATE TABLE novrsoc.cases (
      id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id      uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      number      bigint NOT NULL DEFAULT nextval('novrsoc.case_number_seq') UNIQUE,
      title       text NOT NULL CHECK (length(title) BETWEEN 3 AND 200),
      severity    text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
      status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
      source      text NOT NULL CHECK (source ~ '^[a-z0-9_-]{2,40}$'),
      source_id   text NOT NULL CHECK (length(source_id) BETWEEN 1 AND 200),
      assignee_id uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_by  uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_at  timestamptz NOT NULL DEFAULT now(),
      updated_at  timestamptz NOT NULL DEFAULT now(),
      closed_at   timestamptz,
      UNIQUE (org_id, source, source_id),
      UNIQUE (id, org_id)
    );
    CREATE INDEX cases_org_created ON novrsoc.cases (org_id, created_at DESC);

    CREATE TABLE novrsoc.case_alerts (
      case_id  uuid NOT NULL,
      alert_id uuid NOT NULL,
      org_id   uuid NOT NULL,
      linked_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (case_id, alert_id),
      FOREIGN KEY (case_id, org_id) REFERENCES novrsoc.cases(id, org_id) ON DELETE CASCADE,
      FOREIGN KEY (alert_id, org_id) REFERENCES novrsoc.alerts(id, org_id) ON DELETE CASCADE
    );

    CREATE TABLE novrsoc.case_events (
      id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      case_id     uuid NOT NULL,
      org_id      uuid NOT NULL,
      occurred_at timestamptz NOT NULL DEFAULT now(),
      actor_id    uuid,
      actor_label text NOT NULL DEFAULT '',
      kind        text NOT NULL CHECK (kind IN ('created', 'note', 'status_changed', 'alert_linked')),
      body        text NOT NULL DEFAULT '' CHECK (length(body) <= 8000),
      details     jsonb NOT NULL DEFAULT '{}'::jsonb,
      FOREIGN KEY (case_id, org_id) REFERENCES novrsoc.cases(id, org_id) ON DELETE CASCADE
    );
    CREATE INDEX case_events_case ON novrsoc.case_events (case_id, id);

    ALTER TABLE novrsoc.alerts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.alert_quarantine ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.cases ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.case_alerts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.case_events ENABLE ROW LEVEL SECURITY;
    CREATE POLICY alerts_tenant ON novrsoc.alerts FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    CREATE POLICY alert_quarantine_platform ON novrsoc.alert_quarantine FOR SELECT USING (novrsoc.app_platform_admin());
    CREATE POLICY cases_tenant ON novrsoc.cases FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    CREATE POLICY case_alerts_tenant ON novrsoc.case_alerts FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    CREATE POLICY case_events_tenant ON novrsoc.case_events FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());

    CREATE FUNCTION novrsoc.quarantine_alert(p_source text, p_external_id text, p_reason text, p_groups text[], p_raw jsonb)
      RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        INSERT INTO novrsoc.alert_quarantine (source, external_id, reason, agent_groups, raw)
        VALUES (p_source, p_external_id, p_reason, p_groups, p_raw) ON CONFLICT (source, external_id) DO NOTHING $$;
    REVOKE ALL ON FUNCTION novrsoc.quarantine_alert(text, text, text, text[], jsonb) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.quarantine_alert(text, text, text, text[], jsonb) TO novrsoc_app;

    GRANT SELECT, INSERT, UPDATE ON novrsoc.alerts TO novrsoc_app;
    GRANT SELECT ON novrsoc.alert_quarantine TO novrsoc_app;
    GRANT SELECT, INSERT, UPDATE ON novrsoc.cases TO novrsoc_app;
    GRANT SELECT, INSERT ON novrsoc.case_alerts TO novrsoc_app;
    GRANT SELECT, INSERT ON novrsoc.case_events TO novrsoc_app;
    GRANT USAGE ON SEQUENCE novrsoc.case_number_seq TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP FUNCTION IF EXISTS novrsoc.quarantine_alert(text, text, text, text[], jsonb);
    DROP TABLE IF EXISTS novrsoc.case_events, novrsoc.case_alerts, novrsoc.cases, novrsoc.alert_quarantine, novrsoc.alerts;
    DROP SEQUENCE IF EXISTS novrsoc.case_number_seq;
    """)
