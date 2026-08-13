-- Rollback: re-add the three dropped columns as nullable, matching their
-- original definitions (000008 / 000127). The data was dead (no readers/writers),
-- so there is nothing to restore — this exists only for rollback symmetry.
ALTER TABLE assets       ADD COLUMN IF NOT EXISTS business_unit VARCHAR(100);
ALTER TABLE asset_groups ADD COLUMN IF NOT EXISTS group_type VARCHAR(30) DEFAULT 'manual';
ALTER TABLE asset_groups ADD COLUMN IF NOT EXISTS properties JSONB DEFAULT '{}';
