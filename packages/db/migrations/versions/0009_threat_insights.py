"""Threat Insights engine storage (Phase 5, workstream F).

  * ti_indicators: one organization's indicators (normalized value + type), with provenance (source, source_ref,
    importer, time), TLP, confidence, validity and a stable STIX 2.1 id. Shared feeds are imported PER organization,
    so matching and visibility never cross organizations. RLS on novrsoc.app_org().
  * ti_matches: an indicator matched against one of the SAME organization's stored alerts, with the observable,
    the field it came from, the deterministic confidence (score, band, reasons) and an analyst verdict. Composite
    foreign keys (indicator_id, org_id) and (alert_id, org_id) make a cross-organization match impossible.
Permissions: the existing intel:read / intel:manage.

Revision ID: 0009_threat_insights
Revises: 0008_nhai_jobs
"""
from alembic import op

revision = "0009_threat_insights"
down_revision = "0008_nhai_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE novrsoc.ti_indicators (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id       uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      type         text NOT NULL CHECK (type IN ('ipv4', 'ipv6', 'domain', 'url', 'sha256', 'cve')),
      value        text NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
      tlp          text NOT NULL CHECK (tlp IN ('clear', 'green', 'amber', 'amber_strict', 'red')),
      confidence   integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
      valid_from   timestamptz NOT NULL,
      valid_until  timestamptz,
      stix_id      text NOT NULL CHECK (stix_id ~ '^indicator--[0-9a-f-]{36}$'),
      source       text NOT NULL CHECK (source ~ '^[a-z0-9_.-]{2,60}$'),
      source_ref   text NOT NULL DEFAULT '',
      imported_by  uuid REFERENCES novrsoc.users(id),
      imported_label text NOT NULL DEFAULT '',
      imported_at  timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, type, value, source),
      UNIQUE (id, org_id)
    );
    CREATE INDEX ti_indicators_lookup ON novrsoc.ti_indicators (org_id, type, value);

    CREATE TABLE novrsoc.ti_matches (
      id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id           uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      indicator_id     uuid NOT NULL,
      alert_id         uuid NOT NULL,
      observable_type  text NOT NULL,
      observable_value text NOT NULL,
      source_field     text NOT NULL CHECK (source_field ~ '^[A-Za-z0-9_.\\[\\]]{1,80}$'),
      matched_at       timestamptz NOT NULL DEFAULT now(),
      confidence       integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
      confidence_band  text NOT NULL CHECK (confidence_band IN ('low', 'medium', 'high')),
      confidence_reasons text[] NOT NULL DEFAULT '{}',
      verdict          text NOT NULL DEFAULT 'unreviewed'
                         CHECK (verdict IN ('unreviewed', 'true_positive', 'false_positive', 'benign')),
      verdict_by       uuid REFERENCES novrsoc.users(id),
      verdict_note     text NOT NULL DEFAULT '',
      verdict_at       timestamptz,
      FOREIGN KEY (indicator_id, org_id) REFERENCES novrsoc.ti_indicators (id, org_id) ON DELETE CASCADE,
      FOREIGN KEY (alert_id, org_id) REFERENCES novrsoc.alerts (id, org_id) ON DELETE CASCADE,
      UNIQUE (org_id, indicator_id, alert_id, source_field)
    );
    CREATE INDEX ti_matches_alert ON novrsoc.ti_matches (org_id, alert_id);

    ALTER TABLE novrsoc.ti_indicators ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.ti_matches ENABLE ROW LEVEL SECURITY;
    CREATE POLICY ti_indicators_tenant ON novrsoc.ti_indicators FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    CREATE POLICY ti_matches_tenant ON novrsoc.ti_matches FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT, UPDATE ON novrsoc.ti_indicators TO novrsoc_app;
    GRANT SELECT, INSERT, UPDATE ON novrsoc.ti_matches TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS novrsoc.ti_matches, novrsoc.ti_indicators;")
