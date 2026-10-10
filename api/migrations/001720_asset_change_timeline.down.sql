DROP FUNCTION IF EXISTS asset_change_events_ensure_partitions(DATE, INTEGER);
DROP TABLE IF EXISTS asset_change_events;
ALTER TABLE asset_attribute_sources
    DROP COLUMN IF EXISTS winner,
    DROP COLUMN IF EXISTS source_run;
