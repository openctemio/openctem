-- RFC-046 §11 / RFC-030 §5.7: shared platform sensors serve many tenants,
-- and get_next_platform_job ordered the whole queue by queue_priority, where
-- a tenant's in-flight jobs only subtracted 10 points each and only when the
-- periodic recalculation had run. A tenant that queued thousands of jobs
-- took the shared sensors for hours ahead of a tenant with one.
--
-- The queue is now ordered by priority class (one class up per 30 minutes
-- queued, never into critical), then by the tenant's platform jobs in flight
-- (fewest first), then queue_priority and age as before. Tool and capability
-- gates, the SKIP LOCKED claim and dispatch_attempts are unchanged from
-- migration 000251. The in-flight count reads only acknowledged/running
-- platform jobs, a set bounded by the platform sensors' capacity.
DROP FUNCTION IF EXISTS get_next_platform_job(uuid, text[], text[]);
CREATE FUNCTION get_next_platform_job(p_sensor_id uuid, p_capabilities text[], p_tools text[])
 RETURNS TABLE(command_id uuid, tenant_id uuid, command_type character varying, payload jsonb, queued_at timestamp with time zone, auth_token character varying)
 LANGUAGE plpgsql
AS $function$
DECLARE
    v_command_id UUID;
    v_tenant_id UUID;
    v_command_type VARCHAR;
    v_payload JSONB;
    v_queued_at TIMESTAMPTZ;
    v_auth_token_prefix VARCHAR;
BEGIN
    SELECT c.id, c.tenant_id, c.type, c.payload, c.queued_at, c.auth_token_prefix
    INTO v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix
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

    UPDATE commands
    SET platform_sensor_id = p_sensor_id,
        status = 'acknowledged',
        acknowledged_at = NOW(),
        dispatch_attempts = dispatch_attempts + 1
    WHERE id = v_command_id;

    RETURN QUERY SELECT v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix;
END;
$function$;
