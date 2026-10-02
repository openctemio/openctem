-- Sensor activity timeline and structured build information
-- (docs/architecture/sensors.md "Activity", "Build information").
--
-- 1. sensor_events: what the platform observed about a sensor, written by the
--    server when a heartbeat differs from the stored row (restart, version,
--    SDK, protocol, tools, capacity, content) and at the health transitions
--    (online, offline). Operational history, not the audit log: the audit log
--    keeps administrator actions and stays lean. Coalesced and capped per
--    sensor on write, deleted after the retention period.
-- 2. Build information reported on the heartbeat (or parsed from the
--    User-Agent of older sensors): SDK name and version, sensor product,
--    commit and build time. The sensor version stays in sensors.version.
--
-- Additive: a new table, its indexes, nullable columns.

CREATE TABLE IF NOT EXISTS sensor_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id    UUID NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    type         VARCHAR(40) NOT NULL,
    at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    summary      VARCHAR(500) NOT NULL,
    details      JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Identical events (same type and summary) within the coalescing window
    -- are folded into one row: repeat_count counts them, last_at is the
    -- latest. A flapping sensor gives one row per state, not one per flap.
    repeat_count INTEGER NOT NULL DEFAULT 1,
    last_at      TIMESTAMPTZ,
    CONSTRAINT sensor_events_type_format CHECK (type ~ '^[a-z][a-z_]{0,39}$'),
    CONSTRAINT sensor_events_details_object CHECK (jsonb_typeof(details) = 'object'),
    CONSTRAINT sensor_events_repeat_count_positive CHECK (repeat_count >= 1)
);

COMMENT ON TABLE sensor_events IS
    'Operational timeline of a sensor (restarts, upgrades, protocol/tool/capacity/content changes, online/offline), written by the server from heartbeat diffs. Not the audit log.';

-- The timeline read: one sensor, newest first, keyset on (at, id).
CREATE INDEX IF NOT EXISTS idx_sensor_events_sensor_at
    ON sensor_events (tenant_id, sensor_id, at DESC, id DESC);

-- Retention sweep.
CREATE INDEX IF NOT EXISTS idx_sensor_events_at
    ON sensor_events (at);

-- Job items of the timeline come from commands (never copied): the sensor's
-- claimed and finished commands, newest first.
CREATE INDEX IF NOT EXISTS idx_commands_sensor_activity
    ON commands (tenant_id, sensor_id, COALESCE(completed_at, acknowledged_at) DESC)
    WHERE acknowledged_at IS NOT NULL OR completed_at IS NOT NULL;

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS sdk_name          VARCHAR(64),
    ADD COLUMN IF NOT EXISTS sdk_version       VARCHAR(64),
    ADD COLUMN IF NOT EXISTS sensor_product    VARCHAR(64),
    ADD COLUMN IF NOT EXISTS sensor_commit     VARCHAR(40),
    ADD COLUMN IF NOT EXISTS sensor_build_time TIMESTAMPTZ;

COMMENT ON COLUMN sensors.sdk_name IS 'SDK the sensor is built with (e.g. openctem-sdk-go), from the heartbeat or its User-Agent. Display data.';
COMMENT ON COLUMN sensors.sdk_version IS 'SDK version (normalized, e.g. v0.9.0). Compared with SENSOR_SDK_MIN_VERSION / SENSOR_SDK_LATEST_VERSION.';
COMMENT ON COLUMN sensors.sensor_product IS 'Sensor product name (e.g. openctemio-sensor). The sensor version is sensors.version.';
COMMENT ON COLUMN sensors.sensor_commit IS 'Source commit the sensor binary was built from, when reported.';
COMMENT ON COLUMN sensors.sensor_build_time IS 'Build time of the sensor binary, when reported.';

CREATE INDEX IF NOT EXISTS idx_sensors_tenant_sdk_version
    ON sensors (tenant_id, sdk_version);
