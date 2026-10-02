ALTER TABLE sensors
    DROP COLUMN IF EXISTS protocol_seen_at,
    DROP COLUMN IF EXISTS protocol_client,
    DROP COLUMN IF EXISTS protocol_version;
