-- Restores is_platform_sensor from scope and the triggers of 002433.
-- The old schema gave every sensor a tenant; a shared sensor has none, and
-- no tenant can be chosen for it safely. The downgrade therefore refuses
-- while shared sensors exist: delete them (or re-enroll them under an
-- organization) first.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM sensors WHERE scope = 'instance') THEN
        RAISE EXCEPTION 'cannot downgrade: shared sensors (scope instance) have no tenant; delete them first';
    END IF;
END;
$$;

DROP INDEX IF EXISTS idx_sensors_scope_instance;
ALTER TABLE sensors ADD COLUMN is_platform_sensor boolean NOT NULL DEFAULT false;
CREATE INDEX idx_sensors_platform ON sensors USING btree (is_platform_sensor) WHERE (is_platform_sensor = true);

DROP TRIGGER IF EXISTS trigger_sensors_scope_immutable ON sensors;
DROP FUNCTION IF EXISTS sensors_scope_immutable();
DROP TRIGGER IF EXISTS trigger_sensor_grants_tenant_scope ON sensor_grants;
DROP TRIGGER IF EXISTS trigger_sensor_keys_tenant_scope ON sensor_keys;
DROP FUNCTION IF EXISTS sensor_child_tenant_matches_scope();

ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_scope_tenant;
ALTER TABLE sensors ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE sensor_grants DROP CONSTRAINT IF EXISTS fk_sensor_grants_sensor_id;
ALTER TABLE sensor_keys DROP CONSTRAINT IF EXISTS fk_sensor_keys_sensor_id;
ALTER TABLE sensor_grants ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE sensor_keys ALTER COLUMN tenant_id SET NOT NULL;

CREATE OR REPLACE FUNCTION sensor_grants_default() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.is_platform_sensor THEN
        UPDATE sensors SET trust_level = 'trusted' WHERE id = NEW.id;
        INSERT INTO sensor_grants (sensor_id, tenant_id, profile, job_types, tier_ceiling, target_network,
                                   remote_actions)
        VALUES (NEW.id, NEW.tenant_id, 'easm-external', ARRAY['retest', 'scan', 'validate'], 1, 'public',
                ARRAY['diagnostics', 'rotate_key'])
        ON CONFLICT (sensor_id) DO NOTHING;
    ELSIF NEW.type = 'collector' THEN
        INSERT INTO sensor_grants (sensor_id, tenant_id, profile, job_types, tier_ceiling, target_network,
                                   allow_push_ingest)
        VALUES (NEW.id, NEW.tenant_id, 'collector', ARRAY['collect', 'connector_sync'], 0, 'none', TRUE)
        ON CONFLICT (sensor_id) DO NOTHING;
    ELSIF NEW.type = 'sensor' THEN
        INSERT INTO sensor_grants (sensor_id, tenant_id, profile, job_types, tier_ceiling, target_network)
        VALUES (NEW.id, NEW.tenant_id, 'easm-external', ARRAY['retest', 'scan', 'validate'], 1, 'public')
        ON CONFLICT (sensor_id) DO NOTHING;
    ELSE
        INSERT INTO sensor_grants (sensor_id, tenant_id, profile, job_types, tier_ceiling, target_network)
        VALUES (NEW.id, NEW.tenant_id, 'internal-network-scanner', ARRAY['retest', 'scan', 'validate'], 1, 'any')
        ON CONFLICT (sensor_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION sensor_grants_default() IS
    'Insert trigger on sensors: the default grant of a new sensor (easm-external without update for a shared sensor, collector for type collector, easm-external for type sensor, else internal-network-scanner).';

CREATE OR REPLACE FUNCTION clamp_shared_sensor_grant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM sensors s WHERE s.id = NEW.sensor_id AND s.is_platform_sensor) THEN
        NEW.allow_credentials := FALSE;
        NEW.allow_push_ingest := FALSE;
        NEW.tier_ceiling := LEAST(NEW.tier_ceiling, 1);
        IF NEW.target_network = 'any' THEN
            NEW.target_network := 'public';
        END IF;
        NEW.remote_actions := array_remove(NEW.remote_actions, 'update');
        IF NEW.profile = 'legacy-broad' THEN
            NEW.profile := 'easm-external';
            NEW.job_types := COALESCE(NEW.job_types, ARRAY['retest', 'scan', 'validate']);
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION clamp_shared_sensor_grant() IS
    'BEFORE INSERT OR UPDATE on sensor_grants: the grant of a shared (platform) sensor never allows credentials, push ingest, tier 2, any-network targets, remote update or legacy-broad.';

CREATE OR REPLACE FUNCTION clamp_grant_of_new_shared_sensor() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- The no-op update runs clamp_shared_sensor_grant on the row.
    UPDATE sensor_grants SET version = version + 1, updated_at = NOW() WHERE sensor_id = NEW.id;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION clamp_grant_of_new_shared_sensor() IS
    'AFTER UPDATE OF is_platform_sensor on sensors: a sensor flagged shared has its grant clamped at once (clamp_shared_sensor_grant).';

CREATE TRIGGER trigger_clamp_grant_of_new_shared_sensor
    AFTER UPDATE OF is_platform_sensor ON sensors
    FOR EACH ROW WHEN (NEW.is_platform_sensor AND NOT OLD.is_platform_sensor)
    EXECUTE FUNCTION clamp_grant_of_new_shared_sensor();

ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_scope;
ALTER TABLE sensors DROP COLUMN scope;
