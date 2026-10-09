DELETE FROM scope_targets WHERE authorization_source = 'authorization_letter';
DROP INDEX IF EXISTS idx_scope_targets_letter;
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_letter;
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS fk_scope_targets_letter;
ALTER TABLE scope_targets DROP COLUMN IF EXISTS letter_id;
DROP TABLE IF EXISTS authorization_letters;
