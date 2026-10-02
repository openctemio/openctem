ALTER TABLE sensors
    DROP COLUMN IF EXISTS load_reported_at,
    DROP COLUMN IF EXISTS reported_queue,
    DROP COLUMN IF EXISTS reported_capacity,
    DROP COLUMN IF EXISTS reported_resources;
