-- A scope entry can come from a person confirming an asset as the
-- organization's (research/117): its exact entry is added through the scope
-- service with origin confirmed_asset, so the Scope page says where it came
-- from and the entry is easy to find and remove.

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin = ANY (ARRAY[
    'manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system', 'program',
    'confirmed_asset']));
