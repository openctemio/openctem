-- Reverts 000400. Asset rows were not changed by the up migration.

DROP TABLE IF EXISTS asset_type_input_map;

-- Back to the 000243 list. NOT VALID: rows recorded as reclassified while
-- 000400 was applied stay (asset_state_history is append-only).
ALTER TABLE asset_state_history DROP CONSTRAINT IF EXISTS chk_change_type;
ALTER TABLE asset_state_history ADD CONSTRAINT chk_change_type CHECK (change_type IN (
    'appeared', 'disappeared', 'recovered',
    'exposure_changed', 'status_changed',
    'criticality_changed', 'owner_changed', 'compliance_changed',
    'classification_changed', 'internet_exposure_changed',
    'renamed'
)) NOT VALID;

-- The two alias rows whose stored pair changed, as 000310 seeded them.
UPDATE asset_types SET alias_of = 'storage', alias_sub_type = 's3_bucket' WHERE code = 's3_bucket';
UPDATE asset_types SET alias_of = 'database', alias_sub_type = 'data_store' WHERE code = 'data_store';

ALTER TABLE asset_types
    DROP COLUMN IF EXISTS sub_types,
    DROP COLUMN IF EXISTS is_storable;

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
DO $$
DECLARE
    cursor_id uuid := NULL;
BEGIN
    LOOP
        SELECT b.last_id INTO cursor_id FROM asset_registry_backfill(cursor_id, 5000) b;
        EXIT WHEN cursor_id IS NULL;
    END LOOP;
END $$;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;
