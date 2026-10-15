-- A duplicate always names the finding it duplicates (it is a tombstone of
-- that canonical finding). Before this, a plain status change could set
-- `duplicate` with no `duplicate_of`.
--
-- 1. Repair: a duplicate with no canonical finding is not a tombstone of
--    anything, so it returns to `confirmed` (the reopen target), with a
--    timeline entry in the same statement. Idempotent (only orphans match) and
--    per row (each entry carries its own finding's tenant).
-- 2. A canonical finding that is deleted leaves its duplicates with
--    duplicate_of = NULL (ON DELETE SET NULL): a trigger reopens them the same
--    way instead of letting the delete fail on the constraint.
-- 3. The constraint, added NOT VALID and validated after the repair.

WITH orphans AS (
    SELECT id FROM findings
    WHERE status = 'duplicate' AND duplicate_of IS NULL
    FOR UPDATE
), moved AS (
    UPDATE findings f
    SET status = 'confirmed', resolution = NULL, resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
    FROM orphans o
    WHERE f.id = o.id
    RETURNING f.id, f.tenant_id
)
INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
SELECT m.tenant_id, m.id, 'status_changed', 'system',
       jsonb_build_object('old_status', 'duplicate', 'new_status', 'confirmed', 'reason', 'duplicate_link_missing'),
       'system', 'Reopened: marked duplicate without the finding it duplicates'
FROM moved m;

CREATE OR REPLACE FUNCTION reopen_orphaned_duplicate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'duplicate' AND NEW.duplicate_of IS NULL AND OLD.duplicate_of IS NOT NULL THEN
        NEW.status      := 'confirmed';
        NEW.resolution  := NULL;
        NEW.resolved_at := NULL;
        NEW.resolved_by := NULL;
        NEW.updated_at  := NOW();
        INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
        VALUES (NEW.tenant_id, NEW.id, 'status_changed', 'system',
                jsonb_build_object('old_status', 'duplicate', 'new_status', 'confirmed',
                                   'reason', 'canonical_deleted', 'canonical_id', OLD.duplicate_of),
                'system', 'Reopened: the finding it duplicated was deleted');
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION reopen_orphaned_duplicate() IS
    'Reopens a duplicate (to confirmed, with a timeline entry) when its canonical finding is deleted';

CREATE TRIGGER trg_findings_reopen_orphaned_duplicate
    BEFORE UPDATE OF duplicate_of ON findings
    FOR EACH ROW
    EXECUTE FUNCTION reopen_orphaned_duplicate();

ALTER TABLE findings
    ADD CONSTRAINT chk_findings_duplicate_has_target
    CHECK (status <> 'duplicate' OR duplicate_of IS NOT NULL) NOT VALID;

ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_duplicate_has_target;
