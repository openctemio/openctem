ALTER TABLE sensors
    DROP CONSTRAINT IF EXISTS chk_sensors_reported_local_policy,
    DROP COLUMN IF EXISTS local_policy_reported_at,
    DROP COLUMN IF EXISTS reported_local_policy;
