ALTER TABLE sensors
    DROP COLUMN IF EXISTS local_store_reported_at,
    DROP COLUMN IF EXISTS reported_local_store;
