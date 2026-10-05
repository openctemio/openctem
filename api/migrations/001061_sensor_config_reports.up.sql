-- Sensor config report (research/26, docs/rfcs/RFC-033-sensor-manifest.md
-- "Config report").
--
-- A sensor runs preflight checks on itself (settings, state volume, tools,
-- TLS trust, local policy) and sends the results with
-- PUT /api/v2/sensor/config-report; every heartbeat carries the digest the
-- platform returned. The platform keeps the latest report per sensor,
-- sanitized at ingest (closed sets, typed parameters, bounded text, no
-- setting values), and shows it with fix instructions from its own catalog.
-- Display and health data only: a report never widens dispatch.
--
-- 1. sensor_config_reports: one row per sensor, the latest report.
-- 2. sensors.config_report_digest / config_health: the stored report's
--    digest and the platform's health rollup (fleet chip, health reasons).
--    sensors.config_heartbeat_digest: the digest the latest heartbeat
--    echoed, written by the heartbeat UPDATE; it differs from
--    config_report_digest when the stored report is stale.
--
-- Additive: a new table, its index, nullable columns. Safe on a populated
-- sensors table (no rewrite, no backfill).

CREATE TABLE IF NOT EXISTS sensor_config_reports (
    sensor_id   UUID PRIMARY KEY REFERENCES sensors(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    digest      TEXT NOT NULL,
    health      TEXT NOT NULL,
    fail_count  INTEGER NOT NULL DEFAULT 0,
    warn_count  INTEGER NOT NULL DEFAULT 0,
    report      JSONB NOT NULL,
    observed_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT sensor_config_reports_digest_format CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT sensor_config_reports_health_check CHECK (health IN ('ok', 'attention', 'impaired', 'blocked')),
    CONSTRAINT sensor_config_reports_counts_check CHECK (fail_count >= 0 AND warn_count >= 0),
    CONSTRAINT sensor_config_reports_report_object CHECK (jsonb_typeof(report) = 'object')
);

COMMENT ON TABLE sensor_config_reports IS
    'The latest config report of each sensor (research/26): sanitized preflight check results and declared settings (name, set, source, secret, valid; never a value). Untrusted claims, display and health data only.';

CREATE INDEX IF NOT EXISTS idx_sensor_config_reports_tenant
    ON sensor_config_reports (tenant_id);

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS config_report_digest    TEXT,
    ADD COLUMN IF NOT EXISTS config_health           TEXT,
    ADD COLUMN IF NOT EXISTS config_heartbeat_digest TEXT;

ALTER TABLE sensors
    DROP CONSTRAINT IF EXISTS chk_sensors_config_health,
    ADD CONSTRAINT chk_sensors_config_health
        CHECK (config_health IS NULL OR config_health IN ('ok', 'attention', 'impaired', 'blocked'));

COMMENT ON COLUMN sensors.config_report_digest IS 'Digest of the stored config report (sensor_config_reports.digest). NULL: the sensor never sent one.';
COMMENT ON COLUMN sensors.config_health IS 'The platform health rollup of the stored config report: ok, attention, impaired or blocked. NULL: no report.';
COMMENT ON COLUMN sensors.config_heartbeat_digest IS 'The config report digest the latest heartbeat echoed. NULL: it echoed none.';
