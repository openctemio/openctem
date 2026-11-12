-- A scope entry can come from one of the organization's connectors
-- (research/117): after a sync, the public names and addresses it synced get
-- their exact entries with origin connector, so the Scope page says where
-- they came from.

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_targets_origin;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_targets_origin CHECK (origin = ANY (ARRAY[
    'manual', 'request', 'import', 'review_rule', 'refusal_fix', 'seed', 'seed_migration', 'system', 'program',
    'confirmed_asset', 'connector']));
