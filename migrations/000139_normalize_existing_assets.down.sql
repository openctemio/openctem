-- Rollback: Clear dedup review entries created by this migration
DELETE FROM asset_dedup_review WHERE status = 'pending';

-- Note: Asset name normalization cannot be fully reversed as old names
-- are stored in properties.aliases. The normalized names are still valid.
