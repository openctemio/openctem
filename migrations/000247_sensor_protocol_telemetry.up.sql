-- Sensor protocol telemetry (RFC-029 §5.3,
-- docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md): the protocol
-- the sensor's last heartbeat arrived on (1 = deprecated v1, 2 = v2) and its
-- User-Agent (SDK and sensor version), so the Sensors page can show which
-- sensors still speak protocol v1. Written by the heartbeat update that runs
-- anyway; display data from an untrusted process, nothing authorizes on it.
ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS protocol_version smallint,
    ADD COLUMN IF NOT EXISTS protocol_client varchar(256),
    ADD COLUMN IF NOT EXISTS protocol_seen_at timestamptz;

COMMENT ON COLUMN sensors.protocol_version IS 'Sensor protocol of the last heartbeat: 1 (deprecated) or 2 (RFC-029). NULL before the first heartbeat that recorded it.';
COMMENT ON COLUMN sensors.protocol_client IS 'User-Agent of the last heartbeat (printable ASCII, at most 256 bytes). Untrusted, display only.';
COMMENT ON COLUMN sensors.protocol_seen_at IS 'When protocol_version and protocol_client were last written.';
