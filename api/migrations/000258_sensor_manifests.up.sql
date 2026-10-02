-- Sensor manifest (RFC-033, docs/rfcs/RFC-033-sensor-manifest.md): what a
-- sensor is (build, platform, resources, concurrency ceiling, tools with
-- their kind, version, capabilities, target types and content versions),
-- registered with PUT /api/v2/sensor/manifest or derived by the platform from
-- the heartbeat of a sensor that does not send one.
--
-- 1. sensor_manifests: every distinct version per sensor, sanitized, with
--    what was ignored. One row per (sensor, digest): a sensor that goes back
--    to an earlier manifest makes that row current again (current_since).
--    Pruned on write: versions beyond the newest 50 that were last seen more
--    than 90 days ago.
-- 2. sensors.manifest_digest / manifest_at / manifest_source: the current
--    version. The reported_* columns stay the projection dispatch reads.
--
-- Additive: a new table, its index, nullable columns.

CREATE TABLE IF NOT EXISTS sensor_manifests (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id     UUID NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    -- NULL for a platform sensor (no tenant), as sensors.tenant_id.
    tenant_id     UUID REFERENCES tenants(id) ON DELETE CASCADE,
    digest        VARCHAR(71) NOT NULL,
    source        VARCHAR(16) NOT NULL,
    manifest      JSONB NOT NULL,
    ignored       JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_since TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT sensor_manifests_sensor_digest_key UNIQUE (sensor_id, digest),
    CONSTRAINT sensor_manifests_digest_format CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT sensor_manifests_source_check CHECK (source IN ('sensor', 'heartbeat')),
    CONSTRAINT sensor_manifests_manifest_object CHECK (jsonb_typeof(manifest) = 'object'),
    CONSTRAINT sensor_manifests_ignored_array CHECK (jsonb_typeof(ignored) = 'array')
);

COMMENT ON TABLE sensor_manifests IS
    'Versions of a sensor''s manifest (RFC-033): sanitized self-description, one row per distinct digest. Untrusted claims; dispatch reads the reported_* projection on sensors.';

-- History read and pruning: one sensor, most recently current first.
CREATE INDEX IF NOT EXISTS idx_sensor_manifests_sensor_current
    ON sensor_manifests (sensor_id, current_since DESC);

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS manifest_digest VARCHAR(71),
    ADD COLUMN IF NOT EXISTS manifest_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS manifest_source VARCHAR(16);

COMMENT ON COLUMN sensors.manifest_digest IS 'Digest of the current manifest (sensor_manifests.digest); the sensor echoes it on its heartbeat (RFC-033). NULL: none yet.';
COMMENT ON COLUMN sensors.manifest_at IS 'When the current manifest became current.';
COMMENT ON COLUMN sensors.manifest_source IS 'sensor (PUT /api/v2/sensor/manifest) or heartbeat (derived by the platform).';
