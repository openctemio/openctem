-- Migration 000230 (down): restore the agent vocabulary.
--
-- Exact inverse of the up migration, idempotent in the same way. Rows written
-- after the upgrade with the new values (sensor.* audit events, sensors:*
-- grants created by admins) are mapped back as well, so the previous binary
-- finds every name it expects.
--
-- expand-contract-ok: inverse of the coordinated agent→sensor rename (RFC-023 §9.5); run only with the previous binary stopped.

CREATE OR REPLACE FUNCTION pg_temp.rename_table(old_name text, new_name text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF to_regclass('public.' || old_name) IS NOT NULL AND to_regclass('public.' || new_name) IS NULL THEN
        EXECUTE format('ALTER TABLE public.%I RENAME TO %I', old_name, new_name);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.rename_column(tbl text, old_name text, new_name text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = tbl AND column_name = old_name)
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = tbl AND column_name = new_name) THEN
        EXECUTE format('ALTER TABLE public.%I RENAME COLUMN %I TO %I', tbl, old_name, new_name);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.rename_constraint(tbl text, old_name text, new_name text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conrelid = to_regclass('public.' || tbl) AND conname = old_name) THEN
        EXECUTE format('ALTER TABLE public.%I RENAME CONSTRAINT %I TO %I', tbl, old_name, new_name);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION pg_temp.rename_index(old_name text, new_name text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF to_regclass('public.' || old_name) IS NOT NULL AND to_regclass('public.' || new_name) IS NULL THEN
        EXECUTE format('ALTER INDEX public.%I RENAME TO %I', old_name, new_name);
    END IF;
END $$;

-- 12. Provenance values
ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
ALTER TABLE asset_services DISABLE TRIGGER trigger_asset_services_updated_at;
UPDATE assets         SET discovery_source = 'agent' WHERE discovery_source = 'sensor';
UPDATE asset_services SET discovery_source = 'agent' WHERE discovery_source = 'sensor';
ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_source_type;
UPDATE assets SET source_type = 'agent' WHERE source_type = 'sensor';
ALTER TABLE assets ADD CONSTRAINT chk_assets_source_type CHECK (source_type IS NULL OR source_type IN
    ('manual', 'integration', 'discovery', 'import', 'api', 'agent', 'scan'));
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;
ALTER TABLE asset_services ENABLE TRIGGER trigger_asset_services_updated_at;

-- asset_state_history is append-only: rows written as 'sensor' after the
-- upgrade cannot be rewritten. The original constraint comes back validated
-- when there are none, NOT VALID (enforced for new rows only) otherwise.
ALTER TABLE asset_state_history DROP CONSTRAINT IF EXISTS chk_state_history_source;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM asset_state_history WHERE source = 'sensor') THEN
        ALTER TABLE asset_state_history ADD CONSTRAINT chk_state_history_source CHECK (source IS NULL OR source IN
            ('scan', 'manual', 'integration', 'system', 'agent', 'api')) NOT VALID;
    ELSE
        ALTER TABLE asset_state_history ADD CONSTRAINT chk_state_history_source CHECK (source IS NULL OR source IN
            ('scan', 'manual', 'integration', 'system', 'agent', 'api'));
    END IF;
END $$;

-- 11. Stored configuration
UPDATE integrations
SET config = (config - 'sensor_id') || jsonb_build_object('agent_id', config -> 'sensor_id')
WHERE provider = 'tenable' AND config ? 'sensor_id';
UPDATE integrations SET config = jsonb_set(config, '{execution_mode}', '"agent"')
WHERE provider = 'tenable' AND config ->> 'execution_mode' = 'sensor';

UPDATE pipeline_templates
SET settings = (settings - 'sensor_preference')
             || jsonb_build_object('agent_preference', settings -> 'sensor_preference')
WHERE settings ? 'sensor_preference';

-- 10. Notification event types
UPDATE notification_preferences SET muted_types = (
    SELECT jsonb_agg(DISTINCT CASE e WHEN 'sensor.offline' THEN 'agent.offline'
                                     WHEN 'sensor.error'   THEN 'agent.error' ELSE e END)
    FROM jsonb_array_elements_text(muted_types) AS e)
WHERE jsonb_typeof(muted_types) = 'array'
  AND muted_types ?| ARRAY['sensor.offline', 'sensor.error'];

UPDATE integration_notification_extensions SET enabled_event_types = (
    SELECT jsonb_agg(DISTINCT CASE e WHEN 'sensor.offline' THEN 'agent.offline'
                                     WHEN 'sensor.error'   THEN 'agent.error' ELSE e END)
    FROM jsonb_array_elements_text(enabled_event_types) AS e)
WHERE jsonb_typeof(enabled_event_types) = 'array'
  AND enabled_event_types ?| ARRAY['sensor.offline', 'sensor.error'];

-- webhooks is dropped by 001069; the guard keeps a re-run of this migration on a
-- later schema (TestSensorRenameUpgrade) working. Unchanged where the table exists.
DO $$
BEGIN
    IF to_regclass('public.webhooks') IS NOT NULL THEN
        EXECUTE $q$
UPDATE webhooks SET event_types = (
    SELECT array_agg(DISTINCT CASE e WHEN 'sensor.offline' THEN 'agent.offline'
                                     WHEN 'sensor.error'   THEN 'agent.error' ELSE e END)
    FROM unnest(event_types::text[]) AS e)
WHERE event_types::text[] && ARRAY['sensor.offline', 'sensor.error']::text[]
        $q$;
    END IF;
END
$$;

UPDATE event_types SET category = 'agents' WHERE category = 'sensors';
INSERT INTO event_types (id, name, description, category, module_id, default_severity, is_active, metadata, created_at)
SELECT replace(id, 'sensor.', 'agent.'), replace(name, 'Sensor', 'Agent'),
       replace(description, 'sensor', 'agent'), 'agents', module_id,
       default_severity, is_active, metadata, created_at
FROM event_types WHERE id IN ('sensor.offline', 'sensor.error')
ON CONFLICT (id) DO NOTHING;
DELETE FROM event_types WHERE id IN ('sensor.offline', 'sensor.error');

-- 9. Sensor API-key scopes (dynamic: the table may already carry its old name
--    when this file is re-run)
DO $$
BEGIN
    IF to_regclass('public.sensor_api_keys') IS NOT NULL THEN
        EXECUTE $q$
            UPDATE sensor_api_keys SET scopes = (
                SELECT array_agg(DISTINCT CASE s
                    WHEN 'sensor:heartbeat' THEN 'agent:heartbeat'
                    WHEN 'sensor:read'      THEN 'agent:read'
                    WHEN 'sensor:write'     THEN 'agent:write'
                    WHEN 'admin:sensors'    THEN 'admin:agents'
                    ELSE s END)
                FROM unnest(scopes::text[]) AS s)
            WHERE scopes::text[] && ARRAY['sensor:heartbeat', 'sensor:read', 'sensor:write', 'admin:sensors']::text[]
        $q$;
    END IF;
END $$;

-- 8. Permissions
CREATE TEMP TABLE IF NOT EXISTS sensor_perm_unmap (new_id text PRIMARY KEY, old_id text NOT NULL, name text, description text);
INSERT INTO sensor_perm_unmap VALUES
    ('sensors:read',            'agents:read',            'View Agents',     'View scan agents'),
    ('sensors:write',           'agents:write',           'Manage Agents',   'Configure agents'),
    ('sensors:delete',          'agents:delete',          'Delete Agents',   'Remove agents'),
    ('sensors:commands:read',   'agents:commands:read',   'View Commands',   'View agent commands'),
    ('sensors:commands:write',  'agents:commands:write',  'Send Commands',   'Send commands to agents'),
    ('sensors:commands:delete', 'agents:commands:delete', 'Delete Commands', 'Remove agent commands')
ON CONFLICT (new_id) DO NOTHING;

-- The module row must exist before permissions point at it again.
INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active,
                     release_status, parent_module_id, created_at, updated_at, is_core)
SELECT 'agents', 'agents', 'Agents', 'Security scanning agents management',
       icon, category, display_order, is_active, release_status, parent_module_id, created_at, NOW(), is_core
FROM modules WHERE id = 'sensors'
ON CONFLICT (id) DO NOTHING;

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
SELECT m.old_id, 'agents', m.name, m.description, p.is_active, p.created_at
FROM sensor_perm_unmap m JOIN permissions p ON p.id = m.new_id
ON CONFLICT (id) DO NOTHING;

UPDATE role_permissions rp SET permission_id = m.old_id
FROM sensor_perm_unmap m
WHERE rp.permission_id = m.new_id
  AND NOT EXISTS (SELECT 1 FROM role_permissions r2 WHERE r2.role_id = rp.role_id AND r2.permission_id = m.old_id);
DELETE FROM role_permissions WHERE permission_id IN (SELECT new_id FROM sensor_perm_unmap);

UPDATE group_permissions gp SET permission_id = m.old_id
FROM sensor_perm_unmap m
WHERE gp.permission_id = m.new_id
  AND NOT EXISTS (SELECT 1 FROM group_permissions g2 WHERE g2.group_id = gp.group_id AND g2.permission_id = m.old_id);
DELETE FROM group_permissions WHERE permission_id IN (SELECT new_id FROM sensor_perm_unmap);

UPDATE permission_set_items psi SET permission_id = m.old_id
FROM sensor_perm_unmap m
WHERE psi.permission_id = m.new_id
  AND NOT EXISTS (SELECT 1 FROM permission_set_items p2
                  WHERE p2.permission_set_id = psi.permission_set_id AND p2.permission_id = m.old_id);
DELETE FROM permission_set_items WHERE permission_id IN (SELECT new_id FROM sensor_perm_unmap);

UPDATE api_keys k SET scopes = (
    SELECT array_agg(s ORDER BY first_pos)
    FROM (SELECT COALESCE(m.old_id, u.s) AS s, min(u.pos) AS first_pos
          FROM unnest(k.scopes::text[]) WITH ORDINALITY AS u(s, pos)
          LEFT JOIN sensor_perm_unmap m ON m.new_id = u.s
          GROUP BY 1) x)
WHERE k.scopes::text[] && (SELECT array_agg(new_id) FROM sensor_perm_unmap);

DELETE FROM permissions WHERE id IN (SELECT new_id FROM sensor_perm_unmap);

-- 7. Module id
UPDATE modules SET description = replace(description, '(Sensors, ', '(Agents, ')
WHERE id = 'scans' AND description LIKE '%(Sensors, %';
UPDATE modules SET description = 'Agent commands' WHERE id = 'commands' AND description = 'Sensor commands';

UPDATE permissions    SET module_id = 'agents'        WHERE module_id = 'sensors';
UPDATE event_types    SET module_id = 'agents'        WHERE module_id = 'sensors';
UPDATE asset_types    SET module_id = 'agents'        WHERE module_id = 'sensors';
UPDATE modules        SET parent_module_id = 'agents' WHERE parent_module_id = 'sensors';
UPDATE tenant_modules tm SET module_id = 'agents'
WHERE module_id = 'sensors'
  AND NOT EXISTS (SELECT 1 FROM tenant_modules t2 WHERE t2.tenant_id = tm.tenant_id AND t2.module_id = 'agents');
DELETE FROM tenant_modules WHERE module_id = 'sensors';
DELETE FROM modules WHERE id = 'sensors';

-- 6. Functions (restored verbatim)
CREATE OR REPLACE FUNCTION recover_stuck_tenant_commands(p_stuck_threshold_minutes integer, p_max_retries integer)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_commands AS (
        UPDATE commands
        SET agent_id = NULL,
            status = 'pending',
            -- Tenant commands have no other dispatch-attempt accounting, so
            -- count each recovery as an attempt. This gives the max_retries
            -- guard a stopping condition and lets fail_exhausted_commands take
            -- over once the command is exhausted.
            dispatch_attempts = dispatch_attempts + 1
        WHERE is_platform_job = FALSE
        AND status = 'acknowledged'
        AND agent_id IS NOT NULL
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < p_max_retries
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_commands;

    RETURN recovered_count;
END;
$function$;

CREATE OR REPLACE FUNCTION recover_stuck_platform_jobs(p_stuck_threshold_minutes integer, p_max_retries integer)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_jobs AS (
        UPDATE commands
        SET platform_agent_id = NULL,
            agent_id = NULL,
            status = 'pending',
            -- Clearing acknowledged_at keeps the row honest once it is back in
            -- the queue; ClaimForAgent sets it again on the next claim.
            acknowledged_at = NULL,
            -- Count each recovery as a dispatch attempt. Without this the
            -- counter never moves for a platform job and fail_exhausted_commands
            -- (dispatch_attempts >= p_max_retries) can never take over.
            dispatch_attempts = dispatch_attempts + 1
        WHERE is_platform_job = TRUE
        AND status = 'acknowledged'
        -- Claimed by *either* dispatch path: platform_agent_id is what
        -- get_next_platform_job would set, agent_id is what the poll path
        -- actually sets today.
        AND (platform_agent_id IS NOT NULL OR agent_id IS NOT NULL)
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < p_max_retries
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_jobs;

    RETURN recovered_count;
END;
$function$;

DROP FUNCTION IF EXISTS get_next_platform_job(uuid, text[], text[]);
CREATE FUNCTION get_next_platform_job(p_agent_id uuid, p_capabilities text[], p_tools text[])
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
    -- Find and claim the next available job
    SELECT c.id, c.tenant_id, c.type, c.payload, c.queued_at, c.auth_token_prefix
    INTO v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix
    FROM commands c
    WHERE c.is_platform_job = TRUE
    AND c.status = 'pending'
    AND c.platform_agent_id IS NULL
    AND (c.expires_at IS NULL OR c.expires_at > NOW())
    ORDER BY c.queue_priority DESC, c.queued_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED;

    IF v_command_id IS NULL THEN
        RETURN;
    END IF;

    -- Claim the job
    UPDATE commands
    SET platform_agent_id = p_agent_id,
        status = 'acknowledged',
        acknowledged_at = NOW(),
        dispatch_attempts = dispatch_attempts + 1
    WHERE id = v_command_id;

    RETURN QUERY SELECT v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix;
END;
$function$;

-- 5. Trigger and policy
DO $$
BEGIN
    IF to_regclass('public.sensors') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public.sensors'::regclass
                   AND tgname = 'trigger_sensors_updated_at') THEN
            ALTER TRIGGER trigger_sensors_updated_at ON sensors RENAME TO trigger_agents_updated_at;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'sensors'
                   AND policyname = 'sensors_tenant_isolation') THEN
            ALTER POLICY sensors_tenant_isolation ON sensors RENAME TO agents_tenant_isolation;
        END IF;
    END IF;
END $$;

-- 4. Indexes
SELECT pg_temp.rename_index(n, o) FROM (VALUES
    ('idx_agent_api_keys_agent_id',  'idx_sensor_api_keys_sensor_id'),
    ('idx_agent_api_keys_expires',   'idx_sensor_api_keys_expires'),
    ('idx_agent_api_keys_hash',      'idx_sensor_api_keys_hash'),
    ('idx_agent_api_keys_prefix',    'idx_sensor_api_keys_prefix'),
    ('idx_agents_api_key_hash',      'idx_sensors_api_key_hash'),
    ('idx_agents_api_key_prefix',    'idx_sensors_api_key_prefix'),
    ('idx_agents_capabilities',      'idx_sensors_capabilities'),
    ('idx_agents_execution_mode',    'idx_sensors_execution_mode'),
    ('idx_agents_key_expires_at',    'idx_sensors_key_expires_at'),
    ('idx_agents_labels',            'idx_sensors_labels'),
    ('idx_agents_last_offline_at',   'idx_sensors_last_offline_at'),
    ('idx_agents_last_seen_at',      'idx_sensors_last_seen_at'),
    ('idx_agents_load_score',        'idx_sensors_load_score'),
    ('idx_agents_metrics_updated',   'idx_sensors_metrics_updated'),
    ('idx_agents_platform',          'idx_sensors_platform'),
    ('idx_agents_region',            'idx_sensors_region'),
    ('idx_agents_status',            'idx_sensors_status'),
    ('idx_agents_tenant_id',         'idx_sensors_tenant_id'),
    ('idx_agents_tenant_id_pk',      'idx_sensors_tenant_id_pk'),
    ('idx_agents_tenant_status',     'idx_sensors_tenant_status'),
    ('idx_agents_tier',              'idx_sensors_tier'),
    ('idx_agents_tools',             'idx_sensors_tools'),
    ('idx_agents_type',              'idx_sensors_type'),
    ('idx_commands_agent',           'idx_commands_sensor'),
    ('idx_commands_platform_agent',  'idx_commands_platform_sensor'),
    ('idx_scan_sessions_agent',      'idx_scan_sessions_sensor'),
    ('idx_step_runs_agent',          'idx_step_runs_sensor'),
    ('idx_tool_executions_agent',    'idx_tool_executions_sensor')
) AS v(o, n);

-- 3. Constraints
SELECT pg_temp.rename_constraint(t, n, o) FROM (VALUES
    ('sensors',         'agents_pkey',                     'sensors_pkey'),
    ('sensors',         'agents_tenant_id_fkey',           'sensors_tenant_id_fkey'),
    ('sensors',         'chk_agents_execution_mode',       'chk_sensors_execution_mode'),
    ('sensors',         'chk_agents_health',               'chk_sensors_health'),
    ('sensors',         'chk_agents_status',               'chk_sensors_status'),
    ('sensors',         'chk_agents_tier',                 'chk_sensors_tier'),
    ('sensors',         'chk_agents_type',                 'chk_sensors_type'),
    ('sensor_api_keys', 'agent_api_keys_pkey',             'sensor_api_keys_pkey'),
    ('sensor_api_keys', 'agent_api_keys_agent_id_fkey',    'sensor_api_keys_sensor_id_fkey'),
    ('commands',        'commands_agent_id_fkey',          'commands_sensor_id_fkey'),
    ('commands',        'commands_platform_agent_id_fkey', 'commands_platform_sensor_id_fkey'),
    ('scan_sessions',   'scan_sessions_agent_id_fkey',     'scan_sessions_sensor_id_fkey'),
    ('pipeline_runs',   'pipeline_runs_agent_id_fkey',     'pipeline_runs_sensor_id_fkey'),
    ('step_runs',       'step_runs_agent_id_fkey',         'step_runs_sensor_id_fkey'),
    ('tool_executions', 'tool_executions_agent_id_fkey',   'tool_executions_sensor_id_fkey'),
    ('scans',           'chk_scans_agent_preference',      'chk_scans_sensor_preference')
) AS v(t, o, n);

-- 2. Columns
SELECT pg_temp.rename_column(t, n, o) FROM (VALUES
    ('sensors',                  'is_platform_agent', 'is_platform_sensor'),
    ('sensor_api_keys',          'agent_id',          'sensor_id'),
    ('commands',                 'agent_id',          'sensor_id'),
    ('commands',                 'platform_agent_id', 'platform_sensor_id'),
    ('findings',                 'agent_id',          'sensor_id'),
    ('ingest_jobs',              'agent_id',          'sensor_id'),
    ('pipeline_runs',            'agent_id',          'sensor_id'),
    ('runtime_telemetry_events', 'agent_id',          'sensor_id'),
    ('scan_sessions',            'agent_id',          'sensor_id'),
    ('scans',                    'agent_preference',  'sensor_preference'),
    ('step_runs',                'agent_id',          'sensor_id'),
    ('tool_executions',          'agent_id',          'sensor_id')
) AS v(t, o, n);

-- 1. Tables
SELECT pg_temp.rename_table('sensor_api_keys', 'agent_api_keys');
SELECT pg_temp.rename_table('sensors', 'agents');

-- 13. Catalog comments
COMMENT ON TABLE agents IS 'Security scanning agents (workers)';
COMMENT ON TABLE agent_api_keys IS 'API keys for agent authentication (supports rotation)';
COMMENT ON TABLE commands IS 'Task queue for agent commands';
COMMENT ON COLUMN commands.platform_agent_id IS 'Platform agent assigned to execute this job';
COMMENT ON COLUMN commands.dispatch_attempts IS 'Number of times this job was dispatched to an agent';
COMMENT ON COLUMN scans.tags IS 'Tags for routing jobs to specific agents';
COMMENT ON COLUMN scans.run_on_tenant_runner IS 'When true, jobs only run on agents owned by this tenant';
COMMENT ON COLUMN scans.agent_preference IS 'Agent selection mode: auto = best match, tenant = tenant-owned only, platform = shared platform agents';
COMMENT ON TABLE runtime_telemetry_events IS 'EDR/XDR-style runtime events emitted by endpoint agents. Append-only, tenant-scoped, feeds IOC correlator.';
COMMENT ON TABLE rule_bundles IS 'Pre-compiled rule packages for agent download';
