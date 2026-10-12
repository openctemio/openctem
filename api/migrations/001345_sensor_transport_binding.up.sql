-- Sensor protocol v3 (docs/rfcs/RFC-059-sensor-transport-v3.md): the
-- binding a sensor's last heartbeat arrived on and why it is not on gRPC.
-- Protocol telemetry like protocol_version; nullable, no backfill.
ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS protocol_binding varchar(8),
    ADD COLUMN IF NOT EXISTS protocol_fallback_reason varchar(256);

ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_protocol_binding;
ALTER TABLE sensors ADD CONSTRAINT chk_sensors_protocol_binding
    CHECK (protocol_binding IS NULL OR protocol_binding IN ('grpc', 'https', 'v2'));
