ALTER TABLE sensors
    DROP COLUMN IF EXISTS manifest_source,
    DROP COLUMN IF EXISTS manifest_at,
    DROP COLUMN IF EXISTS manifest_digest;

DROP TABLE IF EXISTS sensor_manifests;
