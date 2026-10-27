-- Finding evidence roles and the finding's evidence version
-- (docs/architecture/finding-evidence.md): each evidence item says what it
-- shows (baseline, proof, verification, supporting) and where it sits in the
-- reader's order; findings.evidence_version counts every change to a
-- finding's evidence, so a write-up can say which evidence it was written
-- against.
--
-- Live impact: ADD COLUMN with a constant default is catalog-only on both
-- tables (no rewrite). The CHECK constraints are added NOT VALID and then
-- validated (a scan under a weaker lock). Three statement-level triggers on
-- finding_evidence take no lock beyond the table's own DDL lock.

ALTER TABLE finding_evidence ADD COLUMN IF NOT EXISTS role varchar(16) NOT NULL DEFAULT 'supporting';
ALTER TABLE finding_evidence ADD COLUMN IF NOT EXISTS "position" integer NOT NULL DEFAULT 0;
ALTER TABLE finding_evidence DROP CONSTRAINT IF EXISTS chk_finding_evidence_role;
ALTER TABLE finding_evidence ADD CONSTRAINT chk_finding_evidence_role
    CHECK (role IN ('baseline', 'proof', 'verification', 'supporting')) NOT VALID;
ALTER TABLE finding_evidence VALIDATE CONSTRAINT chk_finding_evidence_role;
ALTER TABLE finding_evidence DROP CONSTRAINT IF EXISTS chk_finding_evidence_position;
ALTER TABLE finding_evidence ADD CONSTRAINT chk_finding_evidence_position
    CHECK ("position" >= 0 AND "position" <= 1000) NOT VALID;
ALTER TABLE finding_evidence VALIDATE CONSTRAINT chk_finding_evidence_position;

COMMENT ON COLUMN finding_evidence.role IS
    'What the item shows: baseline (normal behaviour), proof (the issue), verification (fix check) or supporting.';
COMMENT ON COLUMN finding_evidence."position" IS
    'Reader order within a finding, ascending; equal positions fall back to newest first.';

ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence_version bigint NOT NULL DEFAULT 0;
COMMENT ON COLUMN findings.evidence_version IS
    'Counts changes to the finding''s evidence (added, removed, re-roled, reordered); bumped by triggers on finding_evidence.';

-- A bump of evidence_version is not a change another writer must lose to:
-- the evidence triggers set app.findings_keep_row_version for their own
-- update so row_version (optimistic concurrency of full-row writes) stays.
CREATE OR REPLACE FUNCTION findings_bump_row_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF current_setting('app.findings_keep_row_version', true) = 'on' THEN
        NEW.row_version := OLD.row_version;
    ELSE
        NEW.row_version := OLD.row_version + 1;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION finding_evidence_bump_version(p_pairs uuid[], p_tenants uuid[])
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM set_config('app.findings_keep_row_version', 'on', true);
    -- Lock in id order so two statements touching the same findings cannot deadlock.
    WITH locked AS (
        SELECT f.tenant_id, f.id
        FROM findings f
        JOIN (SELECT DISTINCT t.tenant_id, t.finding_id
              FROM unnest(p_tenants, p_pairs) AS t(tenant_id, finding_id)) d
          ON d.tenant_id = f.tenant_id AND d.finding_id = f.id
        ORDER BY f.id
        FOR UPDATE OF f
    )
    UPDATE findings f SET evidence_version = f.evidence_version + 1
    FROM locked l WHERE f.tenant_id = l.tenant_id AND f.id = l.id;
    PERFORM set_config('app.findings_keep_row_version', 'off', true);
END;
$$;

CREATE OR REPLACE FUNCTION trg_finding_evidence_bump_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM finding_evidence_bump_version(
        (SELECT coalesce(array_agg(finding_id), '{}') FROM new_rows),
        (SELECT coalesce(array_agg(tenant_id), '{}') FROM new_rows));
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION trg_finding_evidence_bump_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM finding_evidence_bump_version(
        (SELECT coalesce(array_agg(finding_id), '{}') FROM old_rows),
        (SELECT coalesce(array_agg(tenant_id), '{}') FROM old_rows));
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION trg_finding_evidence_bump_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM finding_evidence_bump_version(
        (SELECT coalesce(array_agg(n.finding_id), '{}') FROM new_rows n JOIN old_rows o ON o.id = n.id
          WHERE n.role IS DISTINCT FROM o.role OR n."position" IS DISTINCT FROM o."position"
             OR n.content_sha256 IS DISTINCT FROM o.content_sha256),
        (SELECT coalesce(array_agg(n.tenant_id), '{}') FROM new_rows n JOIN old_rows o ON o.id = n.id
          WHERE n.role IS DISTINCT FROM o.role OR n."position" IS DISTINCT FROM o."position"
             OR n.content_sha256 IS DISTINCT FROM o.content_sha256));
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS trg_finding_evidence_bump_insert ON finding_evidence;
CREATE TRIGGER trg_finding_evidence_bump_insert
    AFTER INSERT ON finding_evidence
    REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION trg_finding_evidence_bump_insert();

DROP TRIGGER IF EXISTS trg_finding_evidence_bump_delete ON finding_evidence;
CREATE TRIGGER trg_finding_evidence_bump_delete
    AFTER DELETE ON finding_evidence
    REFERENCING OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION trg_finding_evidence_bump_delete();

DROP TRIGGER IF EXISTS trg_finding_evidence_bump_update ON finding_evidence;
CREATE TRIGGER trg_finding_evidence_bump_update
    AFTER UPDATE ON finding_evidence
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION trg_finding_evidence_bump_update();
