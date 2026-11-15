"""SOC ingest receipts (Phase 5, workstream A slot): explicit, replayable acknowledgements for forwarder batches.

  * ingest_batches records every acknowledged batch: batch_id, the forwarder identity that sent it, a SHA-256 of
    the batch's alert ids (in order) and the counts returned. A replay of the same batch_id by the same identity
    with the same content returns the stored acknowledgement and ingests nothing; the same batch_id with other
    content, or from another identity, is refused (409).
  * The table holds NO organization data (counts only). It is readable only by platform administrators and is
    read and written only through two SECURITY DEFINER functions with a pinned search_path.

Revision ID: 0006_soc_ingest_receipts
Revises: 0005_reports_foundation
"""
from alembic import op

revision = "0006_soc_ingest_receipts"
down_revision = "0005_reports_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE novrsoc.ingest_batches (
      batch_id        text PRIMARY KEY CHECK (length(batch_id) BETWEEN 16 AND 128),
      identity_id     uuid NOT NULL REFERENCES novrsoc.service_identities(id),
      content_sha256  text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
      alert_count     integer NOT NULL CHECK (alert_count BETWEEN 1 AND 100),
      accepted        integer NOT NULL CHECK (accepted >= 0),
      duplicates      integer NOT NULL CHECK (duplicates >= 0),
      quarantined     integer NOT NULL CHECK (quarantined >= 0),
      received_at     timestamptz NOT NULL DEFAULT now(),
      CHECK (accepted + duplicates + quarantined = alert_count)
    );
    CREATE INDEX ingest_batches_received ON novrsoc.ingest_batches (received_at);
    ALTER TABLE novrsoc.ingest_batches ENABLE ROW LEVEL SECURITY;
    CREATE POLICY ingest_batches_platform ON novrsoc.ingest_batches FOR SELECT USING (novrsoc.app_platform_admin());
    GRANT SELECT ON novrsoc.ingest_batches TO novrsoc_app;

    CREATE FUNCTION novrsoc.ingest_batch_lookup(p_batch_id text)
      RETURNS TABLE (identity_id uuid, content_sha256 text, accepted integer, duplicates integer, quarantined integer)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        SELECT b.identity_id, b.content_sha256, b.accepted, b.duplicates, b.quarantined
          FROM novrsoc.ingest_batches b WHERE b.batch_id = p_batch_id $$;

    CREATE FUNCTION novrsoc.ingest_batch_record(p_batch_id text, p_identity uuid, p_sha text, p_count integer,
                                                p_accepted integer, p_duplicates integer, p_quarantined integer)
      RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        WITH ins AS (
          INSERT INTO novrsoc.ingest_batches (batch_id, identity_id, content_sha256, alert_count, accepted, duplicates, quarantined)
          VALUES (p_batch_id, p_identity, p_sha, p_count, p_accepted, p_duplicates, p_quarantined)
          ON CONFLICT (batch_id) DO NOTHING RETURNING 1)
        SELECT EXISTS (SELECT 1 FROM ins) $$;

    REVOKE ALL ON FUNCTION novrsoc.ingest_batch_lookup(text) FROM PUBLIC;
    REVOKE ALL ON FUNCTION novrsoc.ingest_batch_record(text, uuid, text, integer, integer, integer, integer) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.ingest_batch_lookup(text) TO novrsoc_app;
    GRANT EXECUTE ON FUNCTION novrsoc.ingest_batch_record(text, uuid, text, integer, integer, integer, integer) TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP FUNCTION IF EXISTS novrsoc.ingest_batch_record(text, uuid, text, integer, integer, integer, integer);
    DROP FUNCTION IF EXISTS novrsoc.ingest_batch_lookup(text);
    DROP TABLE IF EXISTS novrsoc.ingest_batches;
    """)
