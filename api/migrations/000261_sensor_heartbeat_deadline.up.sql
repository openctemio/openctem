-- Per-sensor heartbeat deadline and suspicion ladder
-- (docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.5, §5.6; owner
-- decisions D1 and D3).
--
-- Each heartbeat stores the interval the sensor follows and the deadline of
-- its next heartbeat, and the health controller judges the sensor against
-- that deadline instead of a global 90 s: online -> late -> stale ->
-- offline (pkg/domain/sensor/liveness.go). late is still dispatchable;
-- stale is not, and its pending pinned work is released; sensor.offline is
-- notified only at offline.
--
-- reported_control is the control-channel report of the last heartbeat that
-- carried one (sdk-go: interval_s, gap_s, lag_ms, build_ms, rtt_ms,
-- failures), clamped at ingest.
--
-- Additive: a row without a deadline (no heartbeat since this migration) is
-- judged against last_seen_at + 60 s, the SDK's default interval.

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS heartbeat_interval_seconds integer,
    ADD COLUMN IF NOT EXISTS heartbeat_due_at timestamptz,
    ADD COLUMN IF NOT EXISTS reported_control jsonb,
    ADD COLUMN IF NOT EXISTS control_reported_at timestamptz;

ALTER TABLE sensors
    DROP CONSTRAINT IF EXISTS chk_sensors_heartbeat_interval,
    ADD CONSTRAINT chk_sensors_heartbeat_interval
        CHECK (heartbeat_interval_seconds IS NULL OR heartbeat_interval_seconds BETWEEN 1 AND 300);

ALTER TABLE sensors
    DROP CONSTRAINT IF EXISTS chk_sensors_health,
    ADD CONSTRAINT chk_sensors_health
        CHECK (health IN ('unknown', 'online', 'late', 'stale', 'offline', 'error'));

COMMENT ON COLUMN sensors.heartbeat_interval_seconds IS 'Heartbeat interval the sensor follows, stored at its last heartbeat (reported control.interval_s or the advised interval, 1..300 s). NULL: not heartbeated since migration 000261 (60 s applies).';
COMMENT ON COLUMN sensors.heartbeat_due_at IS 'When the next heartbeat is due: last heartbeat + heartbeat_interval_seconds. The health controller''s ladder is relative to it (RFC-035 §5.6).';
COMMENT ON COLUMN sensors.reported_control IS 'Control-channel report of the last heartbeat that carried one (interval_s, gap_s, lag_ms, build_ms, rtt_ms, failures), clamped. NULL: never reported.';
COMMENT ON COLUMN sensors.control_reported_at IS 'When reported_control was stored.';
COMMENT ON COLUMN sensors.health IS 'Automatic heartbeat state: unknown, online, late (past its deadline, still dispatchable), stale (not dispatchable), offline, error.';
