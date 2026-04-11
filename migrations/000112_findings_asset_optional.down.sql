DROP INDEX IF EXISTS idx_findings_asset_id_notnull;

-- Restore NOT NULL. Will fail if any rows have asset_id = NULL — manual
-- cleanup required first (DELETE pentest findings without asset, or backfill
-- with a placeholder asset).
ALTER TABLE findings
    ALTER COLUMN asset_id SET NOT NULL;
