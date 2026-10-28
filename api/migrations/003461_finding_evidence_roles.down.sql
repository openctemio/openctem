DROP TRIGGER IF EXISTS trg_finding_evidence_bump_update ON finding_evidence;
DROP TRIGGER IF EXISTS trg_finding_evidence_bump_delete ON finding_evidence;
DROP TRIGGER IF EXISTS trg_finding_evidence_bump_insert ON finding_evidence;
DROP FUNCTION IF EXISTS trg_finding_evidence_bump_update();
DROP FUNCTION IF EXISTS trg_finding_evidence_bump_delete();
DROP FUNCTION IF EXISTS trg_finding_evidence_bump_insert();
DROP FUNCTION IF EXISTS finding_evidence_bump_version(uuid[], uuid[]);

CREATE OR REPLACE FUNCTION findings_bump_row_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END;
$$;

ALTER TABLE findings DROP COLUMN IF EXISTS evidence_version;
ALTER TABLE finding_evidence DROP CONSTRAINT IF EXISTS chk_finding_evidence_position;
ALTER TABLE finding_evidence DROP CONSTRAINT IF EXISTS chk_finding_evidence_role;
ALTER TABLE finding_evidence DROP COLUMN IF EXISTS "position";
ALTER TABLE finding_evidence DROP COLUMN IF EXISTS role;
