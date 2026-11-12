DROP TABLE IF EXISTS scope_target_ci_trusts;
-- Entries a trust created stay as imported entries.
UPDATE scope_targets SET origin = 'import' WHERE origin = 'ci_trust';
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin = ANY (ARRAY[
    'manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system', 'program',
    'confirmed_asset', 'connector']));
ALTER TABLE ci_trust_configs DROP COLUMN IF EXISTS manage_scope;
