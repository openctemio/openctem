-- Sensor scope (docs/rfcs/RFC-100-shared-sensors.md §3.1): a sensor belongs
-- either to the instance (a shared sensor, no tenant) or to one organization.
-- `scope` replaces `is_platform_sensor`, and a shared sensor no longer has a
-- "home" tenant_id: that fake owner is what let a shared row match a tenant's
-- queries and claims.
--
-- Rows that refer to a sensor through (tenant_id, sensor_id):
--   - sensor_grants and sensor_keys may belong to a shared sensor, so their
--     tenant_id becomes nullable (NULL only for a shared sensor, enforced by
--     trigger) and they get a plain FK on sensor_id for the cascade a NULL
--     tenant_id skips;
--   - scan_zone_sensors, sensor_tool_settings, collector_assets and
--     ingest_reports keep tenant_id NOT NULL, so the composite FK refuses a
--     shared sensor there; existing rows of shared sensors are removed.
--
-- The sensors table holds one row per sensor (small); the CHECK is added and
-- validated in place.

-- 1. The column, backfilled from the flag.
ALTER TABLE sensors ADD COLUMN scope varchar(16) NOT NULL DEFAULT 'organization';
UPDATE sensors SET scope = 'instance' WHERE is_platform_sensor;
ALTER TABLE sensors ADD CONSTRAINT chk_sensors_scope CHECK (scope IN ('instance', 'organization'));

COMMENT ON COLUMN sensors.scope IS
    'instance: a shared sensor of the instance (tenant_id NULL, never on the tenant plane); organization: a sensor of tenant_id.';

-- 2. Child rows that may belong to a shared sensor.
ALTER TABLE sensor_grants ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE sensor_keys ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE sensor_grants ADD CONSTRAINT fk_sensor_grants_sensor_id
    FOREIGN KEY (sensor_id) REFERENCES sensors (id) ON DELETE CASCADE;
ALTER TABLE sensor_keys ADD CONSTRAINT fk_sensor_keys_sensor_id
    FOREIGN KEY (sensor_id) REFERENCES sensors (id) ON DELETE CASCADE;

UPDATE sensor_grants g SET tenant_id = NULL FROM sensors s WHERE s.id = g.sensor_id AND s.scope = 'instance';
UPDATE sensor_keys k SET tenant_id = NULL FROM sensors s WHERE s.id = k.sensor_id AND s.scope = 'instance';

-- 3. Organization-only child rows of shared sensors (a shared sensor is never
--    a zone member, has no tenant tool settings, collects no tenant assets and
--    pushes no reports).
DELETE FROM scan_zone_sensors z USING sensors s WHERE s.id = z.sensor_id AND s.scope = 'instance';
DELETE FROM sensor_tool_settings t USING sensors s WHERE s.id = t.sensor_id AND s.scope = 'instance';
DELETE FROM collector_assets c USING sensors s WHERE s.id = c.sensor_id AND s.scope = 'instance';
DELETE FROM ingest_reports r USING sensors s WHERE s.id = r.sensor_id AND s.scope = 'instance';

-- 4. A shared sensor has no tenant.
ALTER TABLE sensors ALTER COLUMN tenant_id DROP NOT NULL;
UPDATE sensors SET tenant_id = NULL WHERE scope = 'instance';
ALTER TABLE sensors ADD CONSTRAINT chk_sensors_scope_tenant CHECK ((scope = 'instance') = (tenant_id IS NULL));

-- 5. A NULL tenant_id on a grant or key belongs to a shared sensor only (a
--    non-NULL one is checked by the composite FK, which a shared sensor never
--    matches).
CREATE OR REPLACE FUNCTION sensor_child_tenant_matches_scope() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.tenant_id IS NULL
       AND NOT EXISTS (SELECT 1 FROM sensors s WHERE s.id = NEW.sensor_id AND s.scope = 'instance') THEN
        RAISE EXCEPTION 'tenant_id may be NULL only for a shared sensor (sensor %)', NEW.sensor_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION sensor_child_tenant_matches_scope() IS
    'BEFORE INSERT OR UPDATE on sensor_grants and sensor_keys: tenant_id is NULL only for a sensor of scope instance.';

CREATE TRIGGER trigger_sensor_grants_tenant_scope
    BEFORE INSERT OR UPDATE OF tenant_id, sensor_id ON sensor_grants
    FOR EACH ROW EXECUTE FUNCTION sensor_child_tenant_matches_scope();
CREATE TRIGGER trigger_sensor_keys_tenant_scope
    BEFORE INSERT OR UPDATE OF tenant_id, sensor_id ON sensor_keys
    FOR EACH ROW EXECUTE FUNCTION sensor_child_tenant_matches_scope();

-- 6. Scope is fixed at creation: moving a sensor between the instance and an
--    organization would carry one owner's history, keys and grant to the
--    other. Re-enroll instead.
CREATE OR REPLACE FUNCTION sensors_scope_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.scope IS DISTINCT FROM OLD.scope THEN
        RAISE EXCEPTION 'sensor scope cannot change (sensor %)', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION sensors_scope_immutable() IS
    'BEFORE UPDATE OF scope on sensors: a sensor keeps the scope it was created with.';

CREATE TRIGGER trigger_sensors_scope_immutable
    BEFORE UPDATE OF scope ON sensors
    FOR EACH ROW EXECUTE FUNCTION sensors_scope_immutable();

-- 7. Functions that read the flag read the scope, and the clamp also limits
--    a shared sensor's job types to scan, validate and retest. A sensor
--    cannot become shared later, so the trigger that clamped a newly flagged
--    sensor goes.
DROP TRIGGER IF EXISTS trigger_clamp_grant_of_new_shared_sensor ON sensors;
DROP FUNCTION IF EXISTS clamp_grant_of_new_shared_sensor();

CREATE OR REPLACE FUNCTION sensor_grants_default() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.scope = 'instance' THEN
        UPDATE sensors SET trust_level = 'trusted' WHERE id = NEW.id;
        INSERT INTO sensor_grants (sensor_id, tenant_id, profile, job_types, tier_ceiling, target_network,
                                   remote_actions)
        VALUES (NEW.id, NULL, 'easm-external', ARRAY['retest', 'scan', 'validate'], 1, 'public',
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
    'Insert trigger on sensors: the default grant of a new sensor (easm-external without update for scope instance, collector for type collector, easm-external for type sensor, else internal-network-scanner).';

CREATE OR REPLACE FUNCTION clamp_shared_sensor_grant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM sensors s WHERE s.id = NEW.sensor_id AND s.scope = 'instance') THEN
        NEW.allow_credentials := FALSE;
        NEW.allow_push_ingest := FALSE;
        NEW.tier_ceiling := LEAST(NEW.tier_ceiling, 1);
        IF NEW.target_network = 'any' THEN
            NEW.target_network := 'public';
        END IF;
        NEW.remote_actions := array_remove(NEW.remote_actions, 'update');
        IF NEW.profile = 'legacy-broad' THEN
            NEW.profile := 'easm-external';
        END IF;
        -- Scan, validate and retest only: no limit becomes exactly these,
        -- any other list its intersection with them (possibly empty).
        NEW.job_types := ARRAY(
            SELECT j FROM unnest(ARRAY['retest', 'scan', 'validate']) AS j
            WHERE NEW.job_types IS NULL OR j = ANY (NEW.job_types)
            ORDER BY j);
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION clamp_shared_sensor_grant() IS
    'BEFORE INSERT OR UPDATE on sensor_grants: the grant of a shared sensor (scope instance) never allows credentials, push ingest, tier 2, any-network targets, remote update, legacy-broad, or job types beyond scan, validate and retest.';

-- Existing shared sensors' grants get the narrowed job types (a handful of
-- rows; the update runs the clamp).
UPDATE sensor_grants g SET version = g.version + 1, updated_at = NOW()
FROM sensors s WHERE s.id = g.sensor_id AND s.scope = 'instance';

-- 8. The flag goes.
-- expand-contract-ok: is_platform_sensor is replaced by scope in this migration and no code reads it (minimal back-compat; the API is stopped during this deploy, see the upgrade note)
DROP INDEX IF EXISTS idx_sensors_platform;
ALTER TABLE sensors DROP COLUMN is_platform_sensor;
CREATE INDEX idx_sensors_scope_instance ON sensors (id) WHERE scope = 'instance';
