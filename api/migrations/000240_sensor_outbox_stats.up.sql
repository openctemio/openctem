-- Sensor outbox state reported on the v1 heartbeat. Expand only.
--
-- The sensor SDK keeps a durable outbox: results written to disk first and
-- delivered when the platform accepts them. A sensor reports the state of that
-- queue on every heartbeat (pending items and bytes, age of the oldest item,
-- dead-lettered items, items evicted by the size/age cap). The API stores the
-- latest snapshot so operators can see a sensor that is online but not
-- delivering.
--
-- outbox_stats is display data reported by an untrusted process, clamped on
-- ingest; nothing authorizes on it. NULL means the sensor never reported an
-- outbox (an SDK without one). A heartbeat without the field leaves both
-- columns untouched, so outbox_reported_at shows how old a snapshot is.
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS outbox_stats JSONB;
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS outbox_reported_at TIMESTAMPTZ;

COMMENT ON COLUMN sensors.outbox_stats IS
    'Latest outbox snapshot from the heartbeat: pending_count, pending_bytes, oldest_age_seconds, dead_letter_count, evicted_count. NULL = never reported.';
COMMENT ON COLUMN sensors.outbox_reported_at IS
    'When outbox_stats was last reported.';
