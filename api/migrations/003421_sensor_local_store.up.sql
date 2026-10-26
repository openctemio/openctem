-- The local store report a sensor sends on its heartbeat (protocol v2
-- feature "local_store"): watermark, whether it stopped claiming jobs and
-- why, bytes per class, disk level, cleanup sweeps. Sanitized JSON, display
-- and health only. Nullable, no default: adding the columns rewrites nothing.
ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS reported_local_store jsonb,
    ADD COLUMN IF NOT EXISTS local_store_reported_at timestamptz;

COMMENT ON COLUMN sensors.reported_local_store IS
    'Last local store report from the sensor heartbeat (untrusted, sanitized): level, stop_claiming, reason, bytes per class, disk level, sweeps.';
COMMENT ON COLUMN sensors.local_store_reported_at IS
    'When reported_local_store was last written.';
