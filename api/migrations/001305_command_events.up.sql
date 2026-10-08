-- What happened to each sensor command, in order (research/62 P0-4): when it
-- was queued, claimed, started, refused, handed back, and how it ended.
-- One row per change, written by a trigger on commands, so every writer
-- (claim, lease reaper, refusal, cancel, result) is covered without each one
-- having to remember to log. A run's timeline is the events of its commands
-- (run_id from payload.scan_run_id). Kept 30 days (command-event-retention).

CREATE TABLE IF NOT EXISTS command_events (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id   UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    command_id  UUID NOT NULL REFERENCES commands (id) ON DELETE CASCADE,
    run_id      UUID,
    event       VARCHAR(20) NOT NULL,
    status      VARCHAR(50),
    attempt     INTEGER NOT NULL DEFAULT 0,
    -- A platform job never names its sensor to the tenant: sensor_id is
    -- stored for operators but the API leaves it out when platform is true.
    platform    BOOLEAN NOT NULL DEFAULT false,
    sensor_id   UUID,
    code        VARCHAR(100),
    message     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_command_events_event CHECK (event IN
        ('queued', 'claimed', 'started', 'requeued', 'refused', 'completed', 'failed', 'canceled', 'expired', 'changed'))
);

CREATE INDEX IF NOT EXISTS idx_command_events_run
    ON command_events (tenant_id, run_id, created_at) WHERE run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_command_events_command ON command_events (command_id, created_at);
CREATE INDEX IF NOT EXISTS idx_command_events_created ON command_events (created_at);

CREATE OR REPLACE FUNCTION record_command_event() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    ev      TEXT;
    sensor  UUID := NEW.sensor_id;
    msg     TEXT;
    code    TEXT;
    run     UUID;
    refusal JSONB;
BEGIN
    IF TG_OP = 'INSERT' THEN
        ev := 'queued';
    ELSIF jsonb_array_length(COALESCE(NEW.refusals, '[]')) > jsonb_array_length(COALESCE(OLD.refusals, '[]')) THEN
        ev := 'refused';
        refusal := NEW.refusals -> -1;
        sensor := COALESCE(OLD.sensor_id, NULLIF(refusal ->> 'sensor_id', '')::uuid);
        code := left(concat_ws('.', refusal ->> 'layer', refusal ->> 'rule'), 100);
        msg := refusal ->> 'detail';
    ELSIF NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NULL;
    ELSIF NEW.status = 'pending' THEN
        ev := 'requeued';
        sensor := OLD.sensor_id;
        msg := NEW.error_message;
    ELSIF NEW.status = 'acknowledged' THEN
        ev := 'claimed';
    ELSIF NEW.status = 'running' THEN
        ev := 'started';
    ELSIF NEW.status IN ('completed', 'failed', 'canceled', 'expired') THEN
        ev := NEW.status;
        IF NEW.status <> 'completed' THEN
            msg := NEW.error_message;
        END IF;
    ELSE
        ev := 'changed';
    END IF;

    BEGIN
        run := NULLIF(NEW.payload ->> 'scan_run_id', '')::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        run := NULL;
    END;

    INSERT INTO command_events (tenant_id, command_id, run_id, event, status, attempt, platform, sensor_id, code, message)
    VALUES (NEW.tenant_id, NEW.id, run, ev, NEW.status, COALESCE(NEW.dispatch_attempts, 0),
            COALESCE(NEW.is_platform_job, false), COALESCE(sensor, NEW.platform_sensor_id), code, left(msg, 2000));
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_command_events ON commands;
CREATE TRIGGER trg_command_events
    AFTER INSERT OR UPDATE OF status, refusals ON commands
    FOR EACH ROW EXECUTE FUNCTION record_command_event();

COMMENT ON TABLE command_events IS 'Lifecycle of each sensor command (queued, claimed, started, refused, requeued, ended), written by trg_command_events; kept 30 days.';
