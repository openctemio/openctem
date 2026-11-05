DROP TABLE IF EXISTS easm_address_auto_adds;

-- Entries added automatically keep existing as system entries.
UPDATE scope_targets SET origin = 'system' WHERE origin = 'auto_address';

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin = ANY (ARRAY[
    'manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system', 'program',
    'confirmed_asset', 'connector', 'ci_trust']));
