-- Restores record_command_event as of shared_claim and drops the columns
-- and the table (the exclusions and the breaker state are forgotten).

SET LOCAL lock_timeout = '5s';

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
            COALESCE(NEW.is_platform_job, false), sensor, code, left(msg, 2000));
    RETURN NULL;
END;
$$;

DROP TABLE IF EXISTS failure_breakers;
ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_commands_failed_on_shape;
ALTER TABLE commands DROP COLUMN IF EXISTS failure_class;
ALTER TABLE commands DROP COLUMN IF EXISTS attempts;
ALTER TABLE commands DROP COLUMN IF EXISTS failed_on;
