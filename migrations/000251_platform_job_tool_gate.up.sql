-- RFC-030 B10: get_next_platform_job accepted p_capabilities and p_tools and
-- never used them, so a platform sensor could claim a job for a tool it does
-- not have and fail it with "scanner not found". The queue now applies the
-- same two gates as the tenant poll (internal/infra/postgres/command_repository.go):
--
--   tool gate:       a job that names a tool (payload "scanner", else
--                    "preferred_tool") is offered only when that tool is in
--                    p_tools;
--   capability gate: a job whose payload carries a required_capabilities
--                    array is offered only when every entry is in
--                    p_capabilities.
--
-- A job that names no tool and requires no capability is offered to any
-- platform sensor, as before. Everything else (ordering, SKIP LOCKED claim,
-- dispatch_attempts) is unchanged from migration 000230.
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
    ORDER BY c.queue_priority DESC, c.queued_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED;

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
