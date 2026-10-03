-- Sensor-local policy report (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
-- §5.7; owner decision Q3 (a)).
--
-- The network owner installs a read-only policy on the sensor host; the
-- sensor enforces it and reports its state ("enforced" or "absent"), digest,
-- a summary (counts, tools, job types, switches; never the ranges) and the
-- live kill switch on its heartbeat and manifest. The platform stores the
-- last report, sanitized at ingest, to show it on the sensor page and to
-- honour the tenant switch that keeps private targets away from sensors
-- without a policy. Display and dispatch-narrowing data only.
--
-- Additive: NULL = never reported (an SDK before RFC-040, or protocol v1).

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS reported_local_policy jsonb,
    ADD COLUMN IF NOT EXISTS local_policy_reported_at timestamptz;

ALTER TABLE sensors
    DROP CONSTRAINT IF EXISTS chk_sensors_reported_local_policy,
    ADD CONSTRAINT chk_sensors_reported_local_policy
        CHECK (reported_local_policy IS NULL OR jsonb_typeof(reported_local_policy) = 'object');

COMMENT ON COLUMN sensors.reported_local_policy IS 'The sensor-local policy report of the last heartbeat or manifest that carried one (RFC-040 §5.7): state, source, digest, summary, kill_switch, warnings. NULL = never reported.';
COMMENT ON COLUMN sensors.local_policy_reported_at IS 'When reported_local_policy was last written.';
