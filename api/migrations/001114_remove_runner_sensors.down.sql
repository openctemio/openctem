-- The type is accepted again; deleted runner sensors and their keys are not
-- restored (they were credentials, re-create one if needed).
ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_type;
ALTER TABLE sensors ADD CONSTRAINT chk_sensors_type
    CHECK (type IN ('worker', 'agent', 'scanner', 'collector', 'platform', 'runner', 'sensor'));
