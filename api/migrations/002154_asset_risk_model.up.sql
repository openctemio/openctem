-- Likelihood-impact asset risk model (api/docs/architecture/asset-risk-score.md).
--
-- 1. Organizations still on the built-in settings (no risk_scoring section,
--    or the "legacy" or "default" preset) move to the new default preset:
--    risk = findings score x exposure% x criticality% x (1 - control
--    reduction). An organization that customized its formula (any other
--    preset) keeps it. Keys outside the formula (floor_unowned_at_p2) are
--    kept: the new values are merged over the old section.
-- 2. Compensating controls now lower the score: linking or unlinking a
--    control, or changing its status, test result, reduction or expiry,
--    rescores the assets it covers.
-- 3. Every live asset is queued once, so scores move to the new model.
--
-- Live impact: an UPDATE of the matching tenants rows, two triggers on the
-- compensating-control tables, one INSERT into asset_risk_queue.

UPDATE tenants
SET settings = jsonb_set(
        settings,
        '{risk_scoring}',
        COALESCE(settings->'risk_scoring', '{}'::jsonb) || '{"preset":"default","weights":{"exposure":35,"criticality":25,"findings":30,"ctem":10},"exposure_scores":{"public":100,"restricted":90,"private":75,"isolated":50,"unknown":90},"exposure_multipliers":{"public":1.3,"restricted":1.1,"private":1,"isolated":0.9,"unknown":1},"criticality_scores":{"critical":100,"high":90,"medium":80,"low":60,"none":80},"finding_impact":{"mode":"severity_weighted","per_finding_points":5,"finding_cap":100,"severity_weights":{"critical":20,"high":10,"medium":5,"low":2,"info":1}},"ctem_points":{"enabled":false,"internet_accessible":30,"pii_exposed":20,"phi_exposed":25,"high_risk_compliance":15,"restricted_data":20},"risk_levels":{"critical_min":80,"high_min":60,"medium_min":40,"low_min":20},"score_composition_mode":"likelihood_impact"}'::jsonb,
        true)
WHERE COALESCE(settings->'risk_scoring'->>'preset', '') IN ('', 'legacy', 'default')
  AND NOT COALESCE((settings->>'is_system')::boolean, false);

-- compensating_control_assets has no tenant_id: take it from the asset.
CREATE OR REPLACE FUNCTION asset_risk_enqueue_control_assets() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_risk_queue (asset_id, tenant_id)
    SELECT DISTINCT a.id, a.tenant_id
    FROM changed_rows c
    JOIN assets a ON a.id = c.asset_id
    ORDER BY a.id
    ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
        WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION asset_risk_enqueue_control_assets() IS
    'Statement trigger: queues the assets of compensating-control links that were added or removed.';

CREATE OR REPLACE FUNCTION asset_risk_enqueue_control() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_risk_queue (asset_id, tenant_id)
    SELECT DISTINCT a.id, a.tenant_id
    FROM compensating_control_assets cca
    JOIN assets a ON a.id = cca.asset_id AND a.tenant_id = NEW.tenant_id
    WHERE cca.control_id = NEW.id
    ORDER BY a.id
    ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
        WHERE asset_risk_queue.enqueued_at > EXCLUDED.enqueued_at;
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION asset_risk_enqueue_control() IS
    'Row trigger: queues the assets of a compensating control whose effect changed.';

DROP TRIGGER IF EXISTS trg_control_assets_risk_insert ON compensating_control_assets;
CREATE TRIGGER trg_control_assets_risk_insert
    AFTER INSERT ON compensating_control_assets
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_risk_enqueue_control_assets();

DROP TRIGGER IF EXISTS trg_control_assets_risk_delete ON compensating_control_assets;
CREATE TRIGGER trg_control_assets_risk_delete
    AFTER DELETE ON compensating_control_assets
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_risk_enqueue_control_assets();

DROP TRIGGER IF EXISTS trg_controls_risk_update ON compensating_controls;
CREATE TRIGGER trg_controls_risk_update
    AFTER UPDATE OF status, test_result, reduction_factor, expires_at ON compensating_controls
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status
       OR OLD.test_result IS DISTINCT FROM NEW.test_result
       OR OLD.reduction_factor IS DISTINCT FROM NEW.reduction_factor
       OR OLD.expires_at IS DISTINCT FROM NEW.expires_at)
    EXECUTE FUNCTION asset_risk_enqueue_control();

INSERT INTO asset_risk_queue (asset_id, tenant_id)
SELECT a.id, a.tenant_id
FROM assets a
WHERE a.deleted_at IS NULL AND a.tenant_id IS NOT NULL
ON CONFLICT (asset_id) DO NOTHING;
