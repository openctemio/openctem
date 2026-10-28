-- A command that fails for a reason that is not the target's (research/302):
-- the tool crashed, the binary is missing, the sensor ran out of memory or
-- disk, the content pack is gone, or the sensor was lost while it held the
-- command. Routed work then goes to another eligible sensor and the sensors
-- that already failed it are excluded from later claims.
--
--   failed_on      sensors that failed the command (claim excludes them);
--                  at most 16.
--   attempts       one entry per infrastructure failure: sensor, class,
--                  tool and content versions, time. At most 16. The final
--                  failure message is built from it.
--   failure_class  the infrastructure class that ended the command, or NULL.
--
-- failure_breakers is the fleet stop rule: the same tool and content
-- version failing with an infrastructure class on two different sensors
-- within the window stops moving commands for that key until `until`.
--
-- Constant defaults: no table rewrite.

ALTER TABLE commands ADD COLUMN IF NOT EXISTS failed_on uuid[] NOT NULL DEFAULT '{}'::uuid[];
ALTER TABLE commands ADD COLUMN IF NOT EXISTS attempts jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE commands ADD COLUMN IF NOT EXISTS failure_class text;

ALTER TABLE commands ADD CONSTRAINT chk_commands_failed_on_shape
    CHECK (cardinality(failed_on) <= 16 AND jsonb_typeof(attempts) = 'array' AND jsonb_array_length(attempts) <= 16) NOT VALID;

COMMENT ON COLUMN commands.failed_on IS
    'Sensors that failed this command for an infrastructure reason or lost its lease; the claim excludes them.';
COMMENT ON COLUMN commands.attempts IS
    'Infrastructure failures of this command: [{sensor_id, class, tool, tool_digest, content_digest, at}].';

CREATE TABLE IF NOT EXISTS failure_breakers (
    tenant_id         uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    key_hash          text        NOT NULL,
    tool              text        NOT NULL DEFAULT '',
    tool_digest       text        NOT NULL DEFAULT '',
    content_digest    text        NOT NULL DEFAULT '',
    class             text        NOT NULL,
    sensors           uuid[]      NOT NULL DEFAULT '{}'::uuid[],
    window_started_at timestamptz NOT NULL DEFAULT NOW(),
    tripped_at        timestamptz,
    until             timestamptz,
    PRIMARY KEY (tenant_id, key_hash),
    CONSTRAINT chk_failure_breakers_sensors CHECK (cardinality(sensors) <= 16)
);
COMMENT ON TABLE failure_breakers IS
    'Fleet stop rule: a tool and content version that failed with an infrastructure class on two sensors is not moved again until until.';

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
        IF jsonb_array_length(COALESCE(NEW.attempts, '[]')) > jsonb_array_length(COALESCE(OLD.attempts, '[]')) THEN
            code := left('moved.' || regexp_replace(COALESCE(NEW.attempts -> -1 ->> 'class', 'unknown'), '^infra\.', ''), 100);
        END IF;
    ELSIF NEW.status = 'acknowledged' THEN
        ev := 'claimed';
    ELSIF NEW.status = 'running' THEN
        ev := 'started';
    ELSIF NEW.status IN ('completed', 'failed', 'canceled', 'expired') THEN
        ev := NEW.status;
        IF NEW.status <> 'completed' THEN
            msg := NEW.error_message;
        END IF;
        IF NEW.status = 'failed' AND NEW.failure_class IS NOT NULL THEN
            code := left(NEW.failure_class, 100);
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
