-- Back to the profiles before retest: internal-network-scanner and
-- authenticated-scanner scan and validate; easm-external and ci-runner scan;
-- endpoint-agent scans and collects.

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
    ELSE
        INSERT INTO sensor_grants (sensor_id, tenant_id, profile, job_types, tier_ceiling, target_network)
        VALUES (NEW.id, NEW.tenant_id, 'internal-network-scanner', ARRAY['scan', 'validate'], 1, 'any')
        ON CONFLICT (sensor_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

UPDATE sensor_grants
SET job_types = array_remove(job_types, 'retest'),
    version = version + 1,
    updated_at = now()
WHERE profile IN ('easm-external', 'internal-network-scanner', 'authenticated-scanner', 'ci-runner', 'endpoint-agent')
  AND 'retest' = ANY (job_types);

UPDATE sensor_grants
SET job_types = array_remove(job_types, 'validate')
WHERE profile IN ('easm-external', 'ci-runner', 'endpoint-agent')
  AND 'validate' = ANY (job_types);
