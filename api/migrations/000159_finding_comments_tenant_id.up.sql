-- Adds tenant_id to finding_comments and finding_activities so reads
-- can be tenant-scoped without JOIN-ing back to findings on every
-- query. Before this migration, the only way to scope a comment to
-- its tenant was to look up findings.tenant_id through the
-- finding_id FK — and several service-layer paths (VulnerabilityService
-- UpdateFindingComment / DeleteFindingComment) skipped that lookup
-- entirely, creating a full IDOR: tenant A could UPDATE tenant B's
-- comment by knowing the UUID.
--
-- Back-fill copies tenant_id from the parent finding. Subsequent
-- inserts must populate the column explicitly; a trigger enforces the
-- invariant.

BEGIN;

ALTER TABLE finding_comments
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE finding_activities
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

-- Back-fill from the parent finding.
UPDATE finding_comments fc
   SET tenant_id = f.tenant_id
  FROM findings f
 WHERE fc.finding_id = f.id
   AND fc.tenant_id IS NULL;

UPDATE finding_activities fa
   SET tenant_id = f.tenant_id
  FROM findings f
 WHERE fa.finding_id = f.id
   AND fa.tenant_id IS NULL;

-- Enforce NOT NULL once back-fill completes. If any row fails the
-- migration will abort — that indicates orphan comments that predate
-- the finding FK cascade and need manual cleanup first.
ALTER TABLE finding_comments   ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE finding_activities ALTER COLUMN tenant_id SET NOT NULL;

-- Enforce the invariant (comments.tenant_id = findings.tenant_id) via
-- a trigger. A CHECK constraint cannot cross tables, so we use a
-- BEFORE INSERT/UPDATE trigger that raises an exception on mismatch.
CREATE OR REPLACE FUNCTION finding_comment_tenant_matches_finding() RETURNS TRIGGER AS $$
DECLARE
    parent_tenant UUID;
BEGIN
    SELECT tenant_id INTO parent_tenant FROM findings WHERE id = NEW.finding_id;
    IF parent_tenant IS NULL THEN
        RAISE EXCEPTION 'finding % not found', NEW.finding_id;
    END IF;
    IF NEW.tenant_id <> parent_tenant THEN
        RAISE EXCEPTION 'tenant_id mismatch: comment tenant % != finding tenant %',
            NEW.tenant_id, parent_tenant;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_finding_comment_tenant_match ON finding_comments;
CREATE TRIGGER trg_finding_comment_tenant_match
    BEFORE INSERT OR UPDATE ON finding_comments
    FOR EACH ROW
    EXECUTE FUNCTION finding_comment_tenant_matches_finding();

CREATE OR REPLACE FUNCTION finding_activity_tenant_matches_finding() RETURNS TRIGGER AS $$
DECLARE
    parent_tenant UUID;
BEGIN
    SELECT tenant_id INTO parent_tenant FROM findings WHERE id = NEW.finding_id;
    IF parent_tenant IS NULL THEN
        RAISE EXCEPTION 'finding % not found', NEW.finding_id;
    END IF;
    IF NEW.tenant_id <> parent_tenant THEN
        RAISE EXCEPTION 'tenant_id mismatch: activity tenant % != finding tenant %',
            NEW.tenant_id, parent_tenant;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_finding_activity_tenant_match ON finding_activities;
CREATE TRIGGER trg_finding_activity_tenant_match
    BEFORE INSERT OR UPDATE ON finding_activities
    FOR EACH ROW
    EXECUTE FUNCTION finding_activity_tenant_matches_finding();

-- Indexes to support tenant-scoped reads (list all comments in a
-- tenant, list activity feed per tenant). finding_id already has its
-- own index from the original migration so no duplicate here.
CREATE INDEX IF NOT EXISTS idx_finding_comments_tenant_id
    ON finding_comments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_finding_activities_tenant_id
    ON finding_activities(tenant_id);

COMMIT;
