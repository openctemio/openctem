DROP TRIGGER IF EXISTS trg_controls_risk_update ON compensating_controls;
DROP TRIGGER IF EXISTS trg_control_assets_risk_delete ON compensating_control_assets;
DROP TRIGGER IF EXISTS trg_control_assets_risk_insert ON compensating_control_assets;
DROP FUNCTION IF EXISTS asset_risk_enqueue_control();
DROP FUNCTION IF EXISTS asset_risk_enqueue_control_assets();

-- Organizations on the new default go back to the legacy weighted formula.
UPDATE tenants
SET settings = jsonb_set(
        settings,
        '{risk_scoring}',
        settings->'risk_scoring' || '{"preset":"legacy","weights":{"exposure":40,"criticality":25,"findings":35,"ctem":0},"exposure_scores":{"public":100,"restricted":62,"private":37,"isolated":12,"unknown":50},"exposure_multipliers":{"public":1.5,"restricted":1.2,"private":1,"isolated":0.8,"unknown":1},"criticality_scores":{"critical":100,"high":72,"medium":48,"low":24,"none":0},"finding_impact":{"mode":"count","per_finding_points":14,"finding_cap":100,"severity_weights":{"critical":20,"high":10,"medium":5,"low":2,"info":1}},"ctem_points":{"enabled":false,"internet_accessible":0,"pii_exposed":0,"phi_exposed":0,"high_risk_compliance":0,"restricted_data":0},"risk_levels":{"critical_min":80,"high_min":60,"medium_min":40,"low_min":20},"score_composition_mode":"multiply"}'::jsonb,
        true)
WHERE settings->'risk_scoring'->>'score_composition_mode' = 'likelihood_impact'
  AND settings->'risk_scoring'->>'preset' = 'default';

INSERT INTO asset_risk_queue (asset_id, tenant_id)
SELECT a.id, a.tenant_id FROM assets a
WHERE a.deleted_at IS NULL AND a.tenant_id IS NOT NULL
ON CONFLICT (asset_id) DO NOTHING;
