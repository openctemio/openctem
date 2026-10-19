-- Optimistic concurrency for findings (docs/architecture/finding-row-version.md).
-- Every UPDATE of a findings row bumps row_version, whichever writer runs it
-- (the full-row write of the API, the reclassifier, the ingest enrichment, a
-- status batch, a trigger on another table). The full-row write only lands
-- while the row still carries the version it was read at, so a stale copy
-- can no longer put back the columns another writer changed.
--
-- Safe on a populated table: ADD COLUMN with a constant default is a
-- catalog-only change (no rewrite); the trigger is DDL only.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS row_version BIGINT NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION findings_bump_row_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION findings_bump_row_version() IS
    'BEFORE UPDATE trigger on findings: every update bumps row_version by one, so a write of a stale copy can be refused.';

DROP TRIGGER IF EXISTS trg_findings_row_version ON findings;
CREATE TRIGGER trg_findings_row_version
    BEFORE UPDATE ON findings
    FOR EACH ROW
    EXECUTE FUNCTION findings_bump_row_version();

COMMENT ON COLUMN findings.row_version IS
    'Optimistic-concurrency version, bumped by trg_findings_row_version on every update.';
