DROP TRIGGER IF EXISTS trg_tenants_scoring_settings ON tenants;
DROP TRIGGER IF EXISTS trg_sla_policies_scoring_delete ON sla_policies;
DROP TRIGGER IF EXISTS trg_sla_policies_scoring_update ON sla_policies;
DROP TRIGGER IF EXISTS trg_sla_policies_scoring_insert ON sla_policies;
DROP TRIGGER IF EXISTS trg_priority_rules_scoring_delete ON priority_override_rules;
DROP TRIGGER IF EXISTS trg_priority_rules_scoring_update ON priority_override_rules;
DROP TRIGGER IF EXISTS trg_priority_rules_scoring_insert ON priority_override_rules;
DROP TRIGGER IF EXISTS trg_business_services_priority_update ON business_services;
DROP TRIGGER IF EXISTS trg_business_units_priority_update ON business_units;
DROP TRIGGER IF EXISTS trg_business_service_assets_priority_delete ON business_service_assets;
DROP TRIGGER IF EXISTS trg_business_service_assets_priority_insert ON business_service_assets;
DROP TRIGGER IF EXISTS trg_business_unit_assets_priority_delete ON business_unit_assets;
DROP TRIGGER IF EXISTS trg_business_unit_assets_priority_insert ON business_unit_assets;
DROP TRIGGER IF EXISTS trg_assets_priority_update ON assets;
DROP TRIGGER IF EXISTS trg_findings_priority_update ON findings;
DROP TRIGGER IF EXISTS trg_findings_priority_insert ON findings;

DROP FUNCTION IF EXISTS scoring_tenant_settings_changed();
DROP FUNCTION IF EXISTS scoring_sla_policies_changed();
DROP FUNCTION IF EXISTS scoring_rules_changed();
DROP FUNCTION IF EXISTS scoring_record_tenant_change(uuid, text, text, text);
DROP FUNCTION IF EXISTS finding_priority_enqueue_business_service();
DROP FUNCTION IF EXISTS finding_priority_enqueue_business_unit();
DROP FUNCTION IF EXISTS finding_priority_enqueue_members();
DROP FUNCTION IF EXISTS finding_priority_enqueue_asset_row();
DROP FUNCTION IF EXISTS finding_priority_enqueue_finding_update();
DROP FUNCTION IF EXISTS finding_priority_enqueue_from_rows();
DROP FUNCTION IF EXISTS scoring_version(uuid, text, integer);

DROP TABLE IF EXISTS finding_priority_queue;

ALTER TABLE findings DROP COLUMN IF EXISTS priority_scored_at;
ALTER TABLE findings DROP COLUMN IF EXISTS priority_version;
ALTER TABLE assets DROP COLUMN IF EXISTS risk_version;

DROP TABLE IF EXISTS scoring_changes;
