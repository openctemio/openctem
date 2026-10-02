-- When the sensor process started, derived from the uptime_seconds its
-- heartbeat reports (NOW() - uptime). The Sensors page shows the uptime from
-- it; the heartbeat used to discard the value. Display data from an untrusted
-- process: nothing schedules or authorizes on it. Additive and nullable.
ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS process_started_at timestamptz;

COMMENT ON COLUMN sensors.process_started_at IS 'Start time of the sensor process (heartbeat time minus the reported uptime_seconds). NULL until a heartbeat reports an uptime.';
