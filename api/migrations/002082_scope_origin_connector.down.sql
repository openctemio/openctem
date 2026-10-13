-- Entries a connector added keep existing as imported entries.
UPDATE scope_targets SET origin = 'import' WHERE origin = 'connector';

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin = ANY (ARRAY[
    'manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system', 'program',
    'confirmed_asset']));
