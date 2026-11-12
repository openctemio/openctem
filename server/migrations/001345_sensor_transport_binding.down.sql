ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_protocol_binding;
ALTER TABLE sensors
    DROP COLUMN IF EXISTS protocol_fallback_reason,
    DROP COLUMN IF EXISTS protocol_binding;
