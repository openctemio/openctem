-- "Assigned to me" and the fix-applied check look up the assets a user owns
-- (asset_owners by user_id). One statement per file: CREATE INDEX CONCURRENTLY
-- cannot run inside the implicit transaction of a multi-statement migration.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_owners_user ON asset_owners (user_id, asset_id) WHERE user_id IS NOT NULL;
