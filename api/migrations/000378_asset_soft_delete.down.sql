-- Reverts 000378: findings cascade with their asset again. Soft-deleted assets
-- (no findings by construction) are hard-deleted first, so they do not come
-- back as live assets once the column is gone.
SET lock_timeout = '5s';

DELETE FROM assets WHERE deleted_at IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = assets.id);

ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_asset_id_fkey;
ALTER TABLE findings
    ADD CONSTRAINT findings_asset_id_fkey
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE NOT VALID;

ALTER TABLE assets DROP COLUMN IF EXISTS deleted_by;
ALTER TABLE assets DROP COLUMN IF EXISTS deleted_at;

RESET lock_timeout;
