-- Heartbeat history for the Control channel card's 24 h sparkline
-- (docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.5,
-- docs/architecture/sensors.md "Control plane under load").
--
-- One row per tenant sensor per 15-minute bucket, aggregated on write (an
-- upsert per heartbeat), deleted after 48 h by the heartbeat-history
-- retention controller: at most 192 rows per sensor, whatever its
-- heartbeat rate. Additive: a new table and its indexes.

CREATE TABLE IF NOT EXISTS sensor_heartbeat_history (
    sensor_id        UUID NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bucket_start     TIMESTAMPTZ NOT NULL,
    beats            INTEGER NOT NULL DEFAULT 0,
    gap_beats        INTEGER NOT NULL DEFAULT 0,
    sum_gap_seconds  DOUBLE PRECISION NOT NULL DEFAULT 0,
    max_gap_seconds  DOUBLE PRECISION NOT NULL DEFAULT 0,
    max_interval_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    max_lag_ms       BIGINT NOT NULL DEFAULT 0,
    failures         BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (sensor_id, bucket_start),
    CONSTRAINT sensor_heartbeat_history_counts CHECK (beats >= 0 AND gap_beats >= 0 AND gap_beats <= beats)
);

COMMENT ON TABLE sensor_heartbeat_history IS
    'Per-sensor 15-minute buckets of heartbeat arrivals (gaps, timer lag, lost heartbeats) for the 24 h sparkline; kept 48 h (RFC-035 §5.5).';

-- The read: one tenant sensor's recent buckets.
CREATE INDEX IF NOT EXISTS idx_sensor_heartbeat_history_tenant_sensor
    ON sensor_heartbeat_history (tenant_id, sensor_id, bucket_start);

-- The retention sweep.
CREATE INDEX IF NOT EXISTS idx_sensor_heartbeat_history_bucket
    ON sensor_heartbeat_history (bucket_start);
