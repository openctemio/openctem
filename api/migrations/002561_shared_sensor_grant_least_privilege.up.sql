-- A shared (platform) sensor serves many organizations, so its grant is
-- least privilege, whatever writes it (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §5,
-- RFC-023 D14, RFC-040): never tenant credentials, never unsolicited (push)
-- results, never intrusive (tier 2) probes, public targets only, and no
-- remote binary update. Before, the sensors insert trigger gave such a row
-- legacy-broad with credentials, push ingest and tier 2.
--
-- 1. The insert trigger gives a new shared sensor the easm-external grant
--    (scan, validate, retest; tier 1; public targets).
-- 2. A BEFORE INSERT OR UPDATE trigger on sensor_grants clamps the grant of
--    any shared sensor, so neither a later edit nor a sensor flagged shared
--    after it was created keeps a broader grant.
-- 3. A sensor flagged shared later has its grant clamped at once.
-- 4. Existing grants of shared sensors are clamped (a handful of rows).

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

CREATE TRIGGER trigger_clamp_shared_sensor_grant
    BEFORE INSERT OR UPDATE ON sensor_grants
    FOR EACH ROW EXECUTE FUNCTION clamp_shared_sensor_grant();

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

-- Existing shared sensors (a handful of rows; the update runs the clamp).
UPDATE sensor_grants g SET version = g.version + 1, updated_at = NOW()
FROM sensors s
WHERE s.id = g.sensor_id AND s.is_platform_sensor
  AND (g.allow_credentials OR g.allow_push_ingest OR g.tier_ceiling > 1 OR g.target_network = 'any'
       OR 'update' = ANY (g.remote_actions) OR g.profile = 'legacy-broad');
