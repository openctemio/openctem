-- A profile that may scan may also validate and retest (RFC-052 §5.2): a
-- retest re-runs one finding's own rule with the tool that found it, on the
-- target it was found on, rated at that detection's tier, so it stays inside
-- the same targets, zones and tier ceiling as the scan. Before, no default
-- profile listed `retest`, so a default sensor never claimed a retest
-- command and "Retest now" waited out its deadline with no result.
--
-- 1. The insert trigger's default grant (internal-network-scanner) lists
--    retest too.
-- 2. Every grant still on a profile that may scan gets the profile's new job
--    types. A grant an administrator edited is on the `custom` profile and
--    is left as it is; legacy-broad has no job type limit (NULL).
--    The version moves so a pending edit of the old row fails its
--    compare-and-swap instead of overwriting this change.

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
        VALUES (NEW.id, NEW.tenant_id, 'internal-network-scanner', ARRAY['retest', 'scan', 'validate'], 1, 'any')
        ON CONFLICT (sensor_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

UPDATE sensor_grants g
SET job_types = (
        SELECT array_agg(DISTINCT t ORDER BY t)
        FROM unnest(g.job_types || ARRAY['retest', 'validate']) AS t
    ),
    version = g.version + 1,
    updated_at = now()
WHERE g.profile IN ('easm-external', 'internal-network-scanner', 'authenticated-scanner', 'ci-runner', 'endpoint-agent')
  AND g.job_types IS NOT NULL
  AND 'scan' = ANY (g.job_types)
  AND NOT (g.job_types @> ARRAY['retest', 'validate']);
