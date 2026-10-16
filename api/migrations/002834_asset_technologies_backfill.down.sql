-- The copied technology rows cannot be told apart from rows ingest wrote
-- since; the previous migration's down drops the table.
DROP TABLE IF EXISTS asset_technology_backfill_removed;
DROP TABLE IF EXISTS asset_technology_backfill;
