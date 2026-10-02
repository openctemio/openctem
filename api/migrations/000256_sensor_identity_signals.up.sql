-- Sensor identity signals (RFC-032 Phase 0,
-- docs/rfcs/RFC-032-sensor-enrollment-and-identity.md §10.2).
--
-- 1. Where the key was last used from: the client address (trusted-proxy
--    rule) and time of the last authenticated request with any of the
--    sensor's keys. sensor_api_keys already has last_used_ip / last_used_at
--    per key row; these cover the inline key and give one place to compare
--    the next request with.
-- 2. Cloned-identity detection: the instance of the last heartbeat that
--    changed it, the recent-instances memory the detector works on, and the
--    time the identity was flagged as cloned (two live processes using one
--    key).
--
-- Additive: nullable columns and one JSONB column with a default. Nothing
-- reads them until this release, and nothing breaks if they stay empty.

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS api_key_last_used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS api_key_last_used_ip INET,
    ADD COLUMN IF NOT EXISTS instance_id          VARCHAR(64),
    ADD COLUMN IF NOT EXISTS instance_state       JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS identity_cloned_at   TIMESTAMPTZ;

ALTER TABLE sensors
    DROP CONSTRAINT IF EXISTS sensors_instance_state_object;
ALTER TABLE sensors
    ADD CONSTRAINT sensors_instance_state_object CHECK (jsonb_typeof(instance_state) = 'object');

COMMENT ON COLUMN sensors.api_key_last_used_at IS 'Last authenticated request with any of the sensor''s keys (RFC-032 Phase 0).';
COMMENT ON COLUMN sensors.api_key_last_used_ip IS 'Client address of that request, resolved with the trusted-proxy rule; never a header the sensor sets.';
COMMENT ON COLUMN sensors.instance_id IS 'Process instance of the last heartbeat that changed it: the SDK-generated instance id, or host:<hash> derived from the hostname for older SDKs.';
COMMENT ON COLUMN sensors.instance_state IS 'Clone-detection memory: recently seen instances and the times a replaced instance came back (pkg/domain/sensor/identity.go).';
COMMENT ON COLUMN sensors.identity_cloned_at IS 'When two live instances were seen using the same key; NULL = not flagged. Cleared when the key is regenerated.';

-- The fleet view filters on flagged sensors; few rows ever match.
CREATE INDEX IF NOT EXISTS idx_sensors_identity_cloned
    ON sensors (tenant_id)
    WHERE identity_cloned_at IS NOT NULL;
