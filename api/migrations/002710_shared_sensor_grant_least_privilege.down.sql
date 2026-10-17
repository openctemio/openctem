-- Removes the clamp triggers and restores the insert trigger of 002084.
-- Grants already clamped stay narrowed (widening a shared sensor's grant
-- back to credentials and push ingest is not restored on purpose).

DROP TRIGGER IF EXISTS trigger_clamp_grant_of_new_shared_sensor ON sensors;
DROP FUNCTION IF EXISTS clamp_grant_of_new_shared_sensor();
DROP TRIGGER IF EXISTS trigger_clamp_shared_sensor_grant ON sensor_grants;
DROP FUNCTION IF EXISTS clamp_shared_sensor_grant();

CREATE OR REPLACE FUNCTION sensor_grants_default() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.is_platform_sensor THEN
        UPDATE sensors SET trust_level = 'trusted' WHERE id = NEW.id;
        INSERT INTO sensor_grants (sensor_id, tenant_id, profile, tier_ceiling, target_network,
                                   allow_credentials, allow_push_ingest, remote_actions)
        VALUES (NEW.id, NEW.tenant_id, 'legacy-broad', 2, 'any', TRUE, TRUE,
                ARRAY['diagnostics', 'rotate_key', 'update'])
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
    'Insert trigger on sensors: the default grant of a new sensor (legacy-broad and trusted for a platform sensor, collector for type collector, easm-external for type sensor, else internal-network-scanner).';
