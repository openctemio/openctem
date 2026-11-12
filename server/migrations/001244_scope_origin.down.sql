ALTER TABLE scope_exclusions DROP CONSTRAINT IF EXISTS chk_scope_exclusions_origin;
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_exclusions DROP COLUMN IF EXISTS origin;
ALTER TABLE scope_targets DROP COLUMN IF EXISTS origin;
