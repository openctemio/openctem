DROP TRIGGER IF EXISTS trg_business_services_risk_update ON business_services;
DROP TRIGGER IF EXISTS trg_business_units_risk_update ON business_units;
DROP TRIGGER IF EXISTS trg_business_service_assets_risk_delete ON business_service_assets;
DROP TRIGGER IF EXISTS trg_business_service_assets_risk_insert ON business_service_assets;
DROP TRIGGER IF EXISTS trg_business_unit_assets_risk_delete ON business_unit_assets;
DROP TRIGGER IF EXISTS trg_business_unit_assets_risk_insert ON business_unit_assets;
DROP TRIGGER IF EXISTS trg_assets_risk_update ON assets;
DROP TRIGGER IF EXISTS trg_assets_risk_insert ON assets;
DROP TRIGGER IF EXISTS trg_findings_asset_risk_update ON findings;
DROP TRIGGER IF EXISTS trg_findings_asset_risk_delete ON findings;
DROP TRIGGER IF EXISTS trg_findings_asset_risk_insert ON findings;

DROP FUNCTION IF EXISTS asset_risk_enqueue_business_service();
DROP FUNCTION IF EXISTS asset_risk_enqueue_business_unit();
DROP FUNCTION IF EXISTS asset_risk_enqueue_asset_row();
DROP FUNCTION IF EXISTS asset_risk_enqueue_finding_update();
DROP FUNCTION IF EXISTS asset_risk_enqueue_new_assets();
DROP FUNCTION IF EXISTS asset_risk_enqueue_from_rows();

DROP TABLE IF EXISTS asset_risk_queue;

ALTER TABLE assets DROP COLUMN IF EXISTS risk_scored_at;
