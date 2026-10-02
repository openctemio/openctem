DROP TABLE IF EXISTS asset_identity_backfill;

-- 'renamed' rows may exist and asset_state_history is append-only, so the
-- old check is restored without validating existing rows.
ALTER TABLE asset_state_history DROP CONSTRAINT IF EXISTS chk_change_type;
ALTER TABLE asset_state_history ADD CONSTRAINT chk_change_type CHECK (change_type IN (
    'appeared', 'disappeared', 'recovered',
    'exposure_changed', 'status_changed',
    'criticality_changed', 'owner_changed', 'compliance_changed',
    'classification_changed', 'internet_exposure_changed'
)) NOT VALID;

ALTER TABLE asset_dedup_review DROP COLUMN IF EXISTS evidence;
ALTER TABLE asset_dedup_review DROP COLUMN IF EXISTS reason;

DROP TABLE IF EXISTS asset_identifiers;
