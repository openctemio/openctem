-- Migration 000230: rename the agent vocabulary to sensor (RFC-023 §9.5)
--
-- One coordinated rename of the schema and of the stored values that carry
-- the old vocabulary, so an existing installation upgrades through its normal
-- `migrate up` with no manual data surgery.
--
-- expand-contract-ok: a full rename (RFC-023 §9.5) shipped with the code that uses the new names; renamed columns on shared tables (commands, findings, scan_sessions, …) cannot be served to an old binary by a view, so the upgrade is stop-old → migrate → start-new and no compatibility views are created. See docs/rfcs/RFC-023-sensor-rename-contract.md.
--
-- Idempotent: every step checks the current state first, so the file is safe
-- to re-run and safe on a database a previous attempt left half-way (the whole
-- file normally runs in one transaction, but an operator may have applied
-- parts of it by hand).
--
-- Kept on purpose, with the reason:
--   * audit_logs rows with action 'agent.*' / resource_type 'agent': the audit
--     log is hash-chained; rewriting history would break verification by
--     design. Queries treat both families as one (pkg/domain/audit).
--   * admin_audit_logs, notification_events, webhook_deliveries: history.
--   * asset_state_history rows with source 'agent': the table is append-only
--     (a trigger rejects UPDATE); new rows are written as 'sensor'.
--   * commands.payload key "agent_preference": sensor protocol v1 job content
--     that deployed sensors read (pkg/sensorproto/legacyv1).
--   * sensors.type values (worker, scanner, sensor, collector, runner, agent,
--     platform): the legacy v1 `type` values; RFC-023 §9.1 splits them into
--     role + deployment in a later step.
--   * columns user_agent / actor_agent: the HTTP User-Agent, not a sensor.
--   * the deprecated.* schema: frozen archive tables.
--   * tenant AI mode 'agent' / module 'ai_triage.agent': an LLM agent.

-- ---------------------------------------------------------------------------
-- Helpers (session-local, gone when the migration's connection closes)
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- 1. Tables (row types, sequences-by-OID, FKs, indexes and RLS policies follow)
-- ---------------------------------------------------------------------------
SELECT pg_temp.rename_table('agents', 'sensors');
SELECT pg_temp.rename_table('agent_api_keys', 'sensor_api_keys');

-- ---------------------------------------------------------------------------
-- 2. Columns
-- ---------------------------------------------------------------------------
SELECT pg_temp.rename_column(t, o, n) FROM (VALUES
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

-- ---------------------------------------------------------------------------
-- 3. Constraints (renaming a PK/unique constraint renames its index too)
-- ---------------------------------------------------------------------------
SELECT pg_temp.rename_constraint(t, o, n) FROM (VALUES
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

-- ---------------------------------------------------------------------------
-- 4. Indexes
-- ---------------------------------------------------------------------------
SELECT pg_temp.rename_index(o, n) FROM (VALUES
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

-- ---------------------------------------------------------------------------
-- 5. Trigger and RLS policy (RLS is in shadow mode; the policy is renamed so
--    the names stay consistent when it is switched on)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public.sensors'::regclass
               AND tgname = 'trigger_agents_updated_at') THEN
        ALTER TRIGGER trigger_agents_updated_at ON sensors RENAME TO trigger_sensors_updated_at;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'sensors'
               AND policyname = 'agents_tenant_isolation') THEN
        ALTER POLICY agents_tenant_isolation ON sensors RENAME TO sensors_tenant_isolation;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 6. Functions whose bodies name the old columns (bodies are text, so a
--    column rename does not reach them)
-- ---------------------------------------------------------------------------
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
    -- Find and claim the next available job
    SELECT c.id, c.tenant_id, c.type, c.payload, c.queued_at, c.auth_token_prefix
    INTO v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix
    FROM commands c
    WHERE c.is_platform_job = TRUE
    AND c.status = 'pending'
    AND c.platform_sensor_id IS NULL
    AND (c.expires_at IS NULL OR c.expires_at > NOW())
    ORDER BY c.queue_priority DESC, c.queued_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED;

    IF v_command_id IS NULL THEN
        RETURN;
    END IF;

    -- Claim the job
    UPDATE commands
    SET platform_sensor_id = p_sensor_id,
        status = 'acknowledged',
        acknowledged_at = NOW(),
        dispatch_attempts = dispatch_attempts + 1
    WHERE id = v_command_id;

    RETURN QUERY SELECT v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix;
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
$function$;

CREATE OR REPLACE FUNCTION recover_stuck_tenant_commands(p_stuck_threshold_minutes integer, p_max_retries integer)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_commands AS (
        UPDATE commands
        SET sensor_id = NULL,
            status = 'pending',
            -- Tenant commands have no other dispatch-attempt accounting, so
            -- count each recovery as an attempt. This gives the max_retries
            -- guard a stopping condition and lets fail_exhausted_commands take
            -- over once the command is exhausted.
            dispatch_attempts = dispatch_attempts + 1
        WHERE is_platform_job = FALSE
        AND status = 'acknowledged'
        AND sensor_id IS NOT NULL
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < p_max_retries
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_commands;

    RETURN recovered_count;
END;
$function$;

-- ---------------------------------------------------------------------------
-- 7. Module id: agents → sensors (catalog row, then every reference)
-- ---------------------------------------------------------------------------
INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active,
                     release_status, parent_module_id, created_at, updated_at, is_core)
SELECT 'sensors', 'sensors', 'Sensors', 'Sensors: scanners, agents and collectors that report to the platform',
       icon, category, display_order, is_active, release_status, parent_module_id, created_at, NOW(), is_core
FROM modules WHERE id = 'agents'
ON CONFLICT (id) DO NOTHING;

UPDATE permissions    SET module_id = 'sensors'        WHERE module_id = 'agents';
UPDATE event_types    SET module_id = 'sensors'        WHERE module_id = 'agents';
UPDATE asset_types    SET module_id = 'sensors'        WHERE module_id = 'agents';
UPDATE modules        SET parent_module_id = 'sensors' WHERE parent_module_id = 'agents';
-- tenant_modules is unique on (tenant_id, module_id): move rows that have no
-- sensors twin, drop the rest (a twin exists only after a partial re-run).
UPDATE tenant_modules tm SET module_id = 'sensors'
WHERE module_id = 'agents'
  AND NOT EXISTS (SELECT 1 FROM tenant_modules t2 WHERE t2.tenant_id = tm.tenant_id AND t2.module_id = 'sensors');
DELETE FROM tenant_modules WHERE module_id = 'agents';
DELETE FROM modules WHERE id = 'agents';

UPDATE modules SET description = 'Sensor commands' WHERE id = 'commands' AND description = 'Agent commands';
UPDATE modules SET description = replace(description, '(Agents, ', '(Sensors, ')
WHERE id = 'scans' AND description LIKE '%(Agents, %';

-- ---------------------------------------------------------------------------
-- 8. Permissions renamed in place: agents:* → sensors:*
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE IF NOT EXISTS sensor_perm_map (old_id text PRIMARY KEY, new_id text NOT NULL, name text, description text);
INSERT INTO sensor_perm_map VALUES
    ('agents:read',            'sensors:read',            'View Sensors',    'View sensors'),
    ('agents:write',           'sensors:write',           'Manage Sensors',  'Configure sensors'),
    ('agents:delete',          'sensors:delete',          'Delete Sensors',  'Remove sensors'),
    ('agents:commands:read',   'sensors:commands:read',   'View Commands',   'View sensor commands'),
    ('agents:commands:write',  'sensors:commands:write',  'Send Commands',   'Send commands to sensors'),
    ('agents:commands:delete', 'sensors:commands:delete', 'Delete Commands', 'Remove sensor commands')
ON CONFLICT (old_id) DO NOTHING;

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
SELECT m.new_id, 'sensors', m.name, m.description, p.is_active, p.created_at
FROM sensor_perm_map m JOIN permissions p ON p.id = m.old_id
ON CONFLICT (id) DO NOTHING;

-- role grants (system and custom roles)
UPDATE role_permissions rp SET permission_id = m.new_id
FROM sensor_perm_map m
WHERE rp.permission_id = m.old_id
  AND NOT EXISTS (SELECT 1 FROM role_permissions r2 WHERE r2.role_id = rp.role_id AND r2.permission_id = m.new_id);
DELETE FROM role_permissions WHERE permission_id IN (SELECT old_id FROM sensor_perm_map);

-- group grants
UPDATE group_permissions gp SET permission_id = m.new_id
FROM sensor_perm_map m
WHERE gp.permission_id = m.old_id
  AND NOT EXISTS (SELECT 1 FROM group_permissions g2 WHERE g2.group_id = gp.group_id AND g2.permission_id = m.new_id);
DELETE FROM group_permissions WHERE permission_id IN (SELECT old_id FROM sensor_perm_map);

-- permission sets
UPDATE permission_set_items psi SET permission_id = m.new_id
FROM sensor_perm_map m
WHERE psi.permission_id = m.old_id
  AND NOT EXISTS (SELECT 1 FROM permission_set_items p2
                  WHERE p2.permission_set_id = psi.permission_set_id AND p2.permission_id = m.new_id);
DELETE FROM permission_set_items WHERE permission_id IN (SELECT old_id FROM sensor_perm_map);

-- oct_ API-key scopes (order kept, duplicates collapsed)
UPDATE api_keys k SET scopes = (
    SELECT array_agg(s ORDER BY first_pos)
    FROM (SELECT COALESCE(m.new_id, u.s) AS s, min(u.pos) AS first_pos
          FROM unnest(k.scopes::text[]) WITH ORDINALITY AS u(s, pos)
          LEFT JOIN sensor_perm_map m ON m.old_id = u.s
          GROUP BY 1) x)
WHERE k.scopes::text[] && (SELECT array_agg(old_id) FROM sensor_perm_map);

DELETE FROM permissions WHERE id IN (SELECT old_id FROM sensor_perm_map);

-- ---------------------------------------------------------------------------
-- 9. Sensor API-key scopes
-- ---------------------------------------------------------------------------
UPDATE sensor_api_keys SET scopes = (
    SELECT array_agg(DISTINCT CASE s
        WHEN 'agent:heartbeat' THEN 'sensor:heartbeat'
        WHEN 'agent:read'      THEN 'sensor:read'
        WHEN 'agent:write'     THEN 'sensor:write'
        WHEN 'admin:agents'    THEN 'admin:sensors'
        ELSE s END)
    FROM unnest(scopes::text[]) AS s)
WHERE scopes::text[] && ARRAY['agent:heartbeat', 'agent:read', 'agent:write', 'admin:agents']::text[];

-- ---------------------------------------------------------------------------
-- 10. Notification event types: agent.offline / agent.error → sensor.*
-- ---------------------------------------------------------------------------
INSERT INTO event_types (id, name, description, category, module_id, default_severity, is_active, metadata, created_at)
SELECT replace(id, 'agent.', 'sensor.'), replace(name, 'Agent', 'Sensor'),
       replace(description, 'agent', 'sensor'), 'sensors', 'sensors',
       default_severity, is_active, metadata, created_at
FROM event_types WHERE id IN ('agent.offline', 'agent.error')
ON CONFLICT (id) DO NOTHING;
DELETE FROM event_types WHERE id IN ('agent.offline', 'agent.error');
UPDATE event_types SET category = 'sensors' WHERE category = 'agents';

UPDATE webhooks SET event_types = (
    SELECT array_agg(DISTINCT CASE e WHEN 'agent.offline' THEN 'sensor.offline'
                                     WHEN 'agent.error'   THEN 'sensor.error' ELSE e END)
    FROM unnest(event_types::text[]) AS e)
WHERE event_types::text[] && ARRAY['agent.offline', 'agent.error']::text[];

UPDATE integration_notification_extensions SET enabled_event_types = (
    SELECT jsonb_agg(DISTINCT CASE e WHEN 'agent.offline' THEN 'sensor.offline'
                                     WHEN 'agent.error'   THEN 'sensor.error' ELSE e END)
    FROM jsonb_array_elements_text(enabled_event_types) AS e)
WHERE jsonb_typeof(enabled_event_types) = 'array'
  AND enabled_event_types ?| ARRAY['agent.offline', 'agent.error'];

UPDATE notification_preferences SET muted_types = (
    SELECT jsonb_agg(DISTINCT CASE e WHEN 'agent.offline' THEN 'sensor.offline'
                                     WHEN 'agent.error'   THEN 'sensor.error' ELSE e END)
    FROM jsonb_array_elements_text(muted_types) AS e)
WHERE jsonb_typeof(muted_types) = 'array'
  AND muted_types ?| ARRAY['agent.offline', 'agent.error'];

-- ---------------------------------------------------------------------------
-- 11. Stored configuration
-- ---------------------------------------------------------------------------
-- Pipeline template settings: {"agent_preference": …} → {"sensor_preference": …}
UPDATE pipeline_templates
SET settings = (settings - 'agent_preference')
             || jsonb_build_object('sensor_preference', settings -> 'agent_preference')
WHERE settings ? 'agent_preference';

-- Tenable integrations: execution_mode "agent" → "sensor"; pinned "agent_id" → "sensor_id"
UPDATE integrations SET config = jsonb_set(config, '{execution_mode}', '"sensor"')
WHERE provider = 'tenable' AND config ->> 'execution_mode' = 'agent';
UPDATE integrations
SET config = (config - 'agent_id') || jsonb_build_object('sensor_id', config -> 'agent_id')
WHERE provider = 'tenable' AND config ? 'agent_id';

-- ---------------------------------------------------------------------------
-- 12. Provenance values written by the server: 'agent' → 'sensor'
--     (asset_state_history is append-only — a trigger rejects UPDATE — so its
--     historical rows keep 'agent' and the constraint accepts both)
-- ---------------------------------------------------------------------------
-- A vocabulary change is not an edit of the asset: keep updated_at as it was.
ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
ALTER TABLE asset_services DISABLE TRIGGER trigger_asset_services_updated_at;

ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_source_type;
UPDATE assets SET source_type = 'sensor' WHERE source_type = 'agent';
ALTER TABLE assets ADD CONSTRAINT chk_assets_source_type CHECK (source_type IS NULL OR source_type IN
    ('manual', 'integration', 'discovery', 'import', 'api', 'sensor', 'scan'));

UPDATE assets         SET discovery_source = 'sensor' WHERE discovery_source = 'agent';
UPDATE asset_services SET discovery_source = 'sensor' WHERE discovery_source = 'agent';

ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;
ALTER TABLE asset_services ENABLE TRIGGER trigger_asset_services_updated_at;

ALTER TABLE asset_state_history DROP CONSTRAINT IF EXISTS chk_state_history_source;
ALTER TABLE asset_state_history ADD CONSTRAINT chk_state_history_source CHECK (source IS NULL OR source IN
    ('scan', 'manual', 'integration', 'system', 'sensor', 'agent', 'api'));

-- ---------------------------------------------------------------------------
-- 13. Catalog comments
-- ---------------------------------------------------------------------------
COMMENT ON TABLE sensors IS 'Sensor registry: scanners, agents and collectors that authenticate to the platform with their own key (RFC-023)';
COMMENT ON TABLE sensor_api_keys IS 'API keys for sensor authentication (supports rotation)';
COMMENT ON TABLE commands IS 'Task queue for sensor commands';
COMMENT ON COLUMN commands.platform_sensor_id IS 'Platform sensor assigned to execute this job';
COMMENT ON COLUMN commands.dispatch_attempts IS 'Number of times this job was dispatched to a sensor';
COMMENT ON COLUMN scans.tags IS 'Tags for routing jobs to specific sensors';
COMMENT ON COLUMN scans.run_on_tenant_runner IS 'When true, jobs only run on sensors owned by this tenant';
COMMENT ON COLUMN scans.sensor_preference IS 'Sensor selection mode: auto = best match, tenant = tenant-owned only, platform = shared platform sensors';
COMMENT ON TABLE runtime_telemetry_events IS 'EDR/XDR-style runtime events emitted by endpoint sensors (agent role). Append-only, tenant-scoped, feeds IOC correlator.';
-- rule_bundles was dropped by 001060; guarded so a re-run on a newer schema works.
DO $$ BEGIN
    IF to_regclass('public.rule_bundles') IS NOT NULL THEN
        COMMENT ON TABLE rule_bundles IS 'Pre-compiled rule packages for sensor download';
    END IF;
END $$;
