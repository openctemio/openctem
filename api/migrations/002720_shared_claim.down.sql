-- Restores commands.platform_sensor_id, get_next_platform_job (as of
-- command_settled_host_keys), the functions that read the column, and drops
-- sensors.accepts_unzoned_jobs. The holders of shared jobs stay in sensor_id.

SET LOCAL lock_timeout = '5s';

ALTER TABLE commands ADD COLUMN IF NOT EXISTS platform_sensor_id uuid;
COMMENT ON COLUMN commands.platform_sensor_id IS 'Platform sensor assigned to execute this job';
ALTER TABLE commands ADD CONSTRAINT commands_platform_sensor_id_fkey FOREIGN KEY (platform_sensor_id) REFERENCES sensors(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_commands_platform_sensor ON commands USING btree (platform_sensor_id) WHERE (platform_sensor_id IS NOT NULL);

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

CREATE OR REPLACE FUNCTION public.recover_stuck_platform_jobs(p_stuck_threshold_minutes integer, p_max_retries integer) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_jobs AS (
        UPDATE commands
        SET platform_sensor_id = NULL,
            sensor_id = NULL,
            status = 'pending',
            -- Clearing acknowledged_at keeps the row honest once it is back in
            -- the queue; ClaimForSensor sets it again on the next claim.
            acknowledged_at = NULL,
            -- Count each recovery as a dispatch attempt. Without this the
            -- counter never moves for a platform job and fail_exhausted_commands
            -- (dispatch_attempts >= p_max_retries) can never take over.
            dispatch_attempts = dispatch_attempts + 1
        WHERE is_platform_job = TRUE
        AND status = 'acknowledged'
        -- Claimed by *either* dispatch path: platform_sensor_id is what
        -- get_next_platform_job would set, sensor_id is what the poll path
        -- actually sets today.
        AND (platform_sensor_id IS NOT NULL OR sensor_id IS NOT NULL)
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < p_max_retries
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_jobs;

    RETURN recovered_count;
END;
$$;

CREATE OR REPLACE FUNCTION public.get_next_platform_job(p_sensor_id uuid, p_capabilities text[], p_tools text[]) RETURNS TABLE(command_id uuid, tenant_id uuid, command_type character varying, payload jsonb, queued_at timestamp with time zone, auth_token character varying)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_command_id UUID;
    v_tenant_id UUID;
    v_command_type VARCHAR;
    v_payload JSONB;
    v_queued_at TIMESTAMPTZ;
    v_auth_token_prefix VARCHAR;
    v_host_keys TEXT[];
BEGIN
    SELECT c.id, c.tenant_id, c.type, c.payload, c.queued_at, c.auth_token_prefix, c.host_keys
    INTO v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix, v_host_keys
    FROM commands c
    LEFT JOIN (
        SELECT l.tenant_id, count(*) AS in_flight
        FROM commands l
        WHERE l.is_platform_job = TRUE
          AND l.status IN ('acknowledged', 'running')
        GROUP BY l.tenant_id
    ) load ON load.tenant_id = c.tenant_id
    WHERE c.is_platform_job = TRUE
    AND c.status = 'pending'
    AND c.platform_sensor_id IS NULL
    AND (c.expires_at IS NULL OR c.expires_at > NOW())
    AND (
        COALESCE(NULLIF(c.payload->>'scanner', ''), NULLIF(c.payload->>'preferred_tool', '')) IS NULL
        OR COALESCE(NULLIF(c.payload->>'scanner', ''), NULLIF(c.payload->>'preferred_tool', ''))
           = ANY(COALESCE(p_tools, ARRAY[]::text[]))
    )
    AND (
        jsonb_typeof(c.payload->'required_capabilities') IS DISTINCT FROM 'array'
        OR NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements_text(c.payload->'required_capabilities') AS rc(cap)
            WHERE rc.cap <> ALL(COALESCE(p_capabilities, ARRAY[]::text[]))
        )
    )
    -- Hosts free: no acknowledged or running command of the tenant holds a
    -- conflicting host key.
    AND (c.host_keys IS NULL OR NOT EXISTS (
        SELECT 1 FROM commands hk
        WHERE hk.tenant_id = c.tenant_id
          AND hk.id <> c.id
          AND hk.host_keys IS NOT NULL
          AND hk.status IN ('acknowledged', 'running')
          AND hk.host_keys && ARRAY(
              SELECT CASE WHEN k LIKE 'in:%' THEN 'net:' || substr(k, 4) ELSE k END
              FROM unnest(c.host_keys) AS k
              UNION ALL
              SELECT 'in:' || substr(k, 5) FROM unnest(c.host_keys) AS k WHERE k LIKE 'net:%')
          -- a conflicting key the holder still holds (not released by its
          -- settled targets)
          AND (hk.settled_host_keys IS NULL OR EXISTS (
              SELECT 1 FROM unnest(ARRAY(
                  SELECT CASE WHEN k LIKE 'in:%' THEN 'net:' || substr(k, 4) ELSE k END
                  FROM unnest(c.host_keys) AS k
                  UNION ALL
                  SELECT 'in:' || substr(k, 5) FROM unnest(c.host_keys) AS k WHERE k LIKE 'net:%')) AS ck
              WHERE ck = ANY(hk.host_keys) AND ck <> ALL(hk.settled_host_keys)))))
    ORDER BY
        -- Priority class, one class up per 30 minutes queued, never into
        -- critical and never down on clock skew.
        CASE c.priority
            WHEN 'critical' THEN 1
            ELSE GREATEST(2,
                (CASE c.priority WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END)
                - LEAST(2, GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (NOW() - COALESCE(c.queued_at, c.created_at))) / 1800)::int)))
        END,
        -- Within a class, the tenant with the fewest platform jobs in flight
        -- first: shared sensors are shared fairly across tenants.
        COALESCE(load.in_flight, 0),
        c.queue_priority DESC,
        c.queued_at ASC
    LIMIT 1
    FOR UPDATE OF c SKIP LOCKED;

    IF v_command_id IS NULL THEN
        RETURN;
    END IF;

    IF v_host_keys IS NOT NULL THEN
        -- The claim locks of the job's host buckets, in key order (the keys
        -- and hashing of lockHostKeys), then the hosts are checked again: a
        -- claim of an overlapping command that committed meanwhile wins.
        PERFORM count(pg_advisory_xact_lock(hashtextextended('host|' || v_tenant_id::text || '|' || keys.k, 0)))
        FROM (
            SELECT DISTINCT CASE WHEN k LIKE 'in:%' THEN 'b:' || substr(k, 4)
                                 WHEN k LIKE 'net:%' THEN 'b:' || substr(k, 5)
                                 ELSE k END AS k
            FROM unnest(v_host_keys) AS k
            ORDER BY 1
        ) keys;
        IF EXISTS (
            SELECT 1 FROM commands hk
            WHERE hk.tenant_id = v_tenant_id
              AND hk.id <> v_command_id
              AND hk.host_keys IS NOT NULL
              AND hk.status IN ('acknowledged', 'running')
              AND hk.host_keys && ARRAY(
                  SELECT CASE WHEN k LIKE 'in:%' THEN 'net:' || substr(k, 4) ELSE k END
                  FROM unnest(v_host_keys) AS k
                  UNION ALL
                  SELECT 'in:' || substr(k, 5) FROM unnest(v_host_keys) AS k WHERE k LIKE 'net:%')
              AND (hk.settled_host_keys IS NULL OR EXISTS (
                  SELECT 1 FROM unnest(ARRAY(
                      SELECT CASE WHEN k LIKE 'in:%' THEN 'net:' || substr(k, 4) ELSE k END
                      FROM unnest(v_host_keys) AS k
                      UNION ALL
                      SELECT 'in:' || substr(k, 5) FROM unnest(v_host_keys) AS k WHERE k LIKE 'net:%')) AS ck
                  WHERE ck = ANY(hk.host_keys) AND ck <> ALL(hk.settled_host_keys)))
        ) THEN
            RETURN;
        END IF;
    END IF;

    UPDATE commands
    SET platform_sensor_id = p_sensor_id,
        status = 'acknowledged',
        acknowledged_at = NOW(),
        dispatch_attempts = dispatch_attempts + 1
    WHERE id = v_command_id;

    RETURN QUERY SELECT v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix;
END;
$$;

ALTER TABLE sensors DROP COLUMN IF EXISTS accepts_unzoned_jobs;
