-- A superseded entry authorizes nothing; it comes back as inactive.
DROP INDEX IF EXISTS ux_scope_targets_pending_replacement;

UPDATE scope_targets SET status = 'inactive' WHERE status = 'superseded';

ALTER TABLE scope_targets DROP CONSTRAINT chk_scope_target_status;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_target_status
    CHECK (status IN ('active', 'inactive', 'pending', 'rejected', 'expired'));

ALTER TABLE scope_targets
    DROP CONSTRAINT IF EXISTS fk_scope_targets_superseded_by,
    DROP CONSTRAINT IF EXISTS fk_scope_targets_supersedes,
    DROP COLUMN IF EXISTS superseded_by_id,
    DROP COLUMN IF EXISTS supersedes_id;
