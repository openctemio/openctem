-- Release a running command's hosts per target, not per command
-- (research/130; docs/architecture/scan-stages.md "One sensor per host").
--
-- commands.settled_host_keys, new, holds the host keys a running command
-- no longer needs: its sensor freed them because the targets that needed
-- them settled (heartbeat progress released_keys, ctis
-- politeness.Holding), bounded by the command's own host_keys and only for
-- a command that sensor holds. A holder counts against a pending command
-- only through a conflicting key it has not released, so the next tool's
-- work on a host starts as soon as this command is done with that host. It
-- is reset with the rest of the progress on every claim, so a re-queued
-- command holds all its hosts again.
--
-- get_next_platform_job applies the same holder rule as the tenant claim
-- (hostFreePredicate).
--
-- Live impact: a nullable column, no default, no rewrite, no backfill; the
-- function is replaced in place.

ALTER TABLE commands ADD COLUMN IF NOT EXISTS settled_host_keys text[];

COMMENT ON COLUMN commands.settled_host_keys IS 'Host keys a running command released because the targets that needed them settled; they no longer hold other work back. Reset on every claim. NULL: none released.';

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
