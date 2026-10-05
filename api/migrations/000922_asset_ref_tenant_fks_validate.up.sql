-- Composite tenant foreign keys on asset references (research doc 21b, P1-1:
-- the database backstop for C1/C3/C4).
--
-- Step 3 of 3: validate the existing rows against the constraints 000921
-- added NOT VALID. VALIDATE CONSTRAINT takes SHARE UPDATE EXCLUSIVE on each
-- table (reads and writes continue) and scans it once. 000921's pre-flight
-- already proved no row violates them, and every row written since is
-- checked, so this cannot fail on data that passed the pre-flight.
ALTER TABLE assets VALIDATE CONSTRAINT fk_assets_tenant_parent;
ALTER TABLE asset_access_grants VALIDATE CONSTRAINT fk_asset_access_grants_tenant_asset;
ALTER TABLE asset_attributions VALIDATE CONSTRAINT fk_asset_attributions_tenant_asset;
ALTER TABLE asset_components VALIDATE CONSTRAINT fk_asset_components_tenant_asset;
ALTER TABLE asset_identifiers VALIDATE CONSTRAINT fk_asset_identifiers_tenant_asset;
ALTER TABLE asset_relationships VALIDATE CONSTRAINT fk_asset_relationships_tenant_source_asset;
ALTER TABLE asset_relationships VALIDATE CONSTRAINT fk_asset_relationships_tenant_target_asset;
ALTER TABLE asset_services VALIDATE CONSTRAINT fk_asset_services_tenant_asset;
ALTER TABLE asset_state_history VALIDATE CONSTRAINT fk_asset_state_history_tenant_asset;
ALTER TABLE asset_type_reclassifications VALIDATE CONSTRAINT fk_asset_type_reclassifications_tenant_asset;
ALTER TABLE business_service_assets VALIDATE CONSTRAINT fk_business_service_assets_tenant_asset;
ALTER TABLE business_unit_assets VALIDATE CONSTRAINT fk_business_unit_assets_tenant_asset;
ALTER TABLE easm_dns_check_state VALIDATE CONSTRAINT fk_easm_dns_check_state_tenant_asset;
ALTER TABLE easm_evidence VALIDATE CONSTRAINT fk_easm_evidence_tenant_asset;
ALTER TABLE exposure_events VALIDATE CONSTRAINT fk_exposure_events_tenant_asset;
ALTER TABLE exposures VALIDATE CONSTRAINT fk_exposures_tenant_asset;
ALTER TABLE finding_retests VALIDATE CONSTRAINT fk_finding_retests_tenant_asset;
ALTER TABLE findings VALIDATE CONSTRAINT fk_findings_tenant_asset;
ALTER TABLE pipeline_runs VALIDATE CONSTRAINT fk_pipeline_runs_tenant_asset;
ALTER TABLE relationship_suggestions VALIDATE CONSTRAINT fk_relationship_suggestions_tenant_source_asset;
ALTER TABLE relationship_suggestions VALIDATE CONSTRAINT fk_relationship_suggestions_tenant_target_asset;
ALTER TABLE runtime_telemetry_events VALIDATE CONSTRAINT fk_runtime_telemetry_events_tenant_endpoint_asset;
ALTER TABLE scan_coverage_state VALIDATE CONSTRAINT fk_scan_coverage_state_tenant_asset;
ALTER TABLE scan_sessions VALIDATE CONSTRAINT fk_scan_sessions_tenant_asset;
ALTER TABLE sla_policies VALIDATE CONSTRAINT fk_sla_policies_tenant_asset;
ALTER TABLE suppression_rules VALIDATE CONSTRAINT fk_suppression_rules_tenant_asset;
ALTER TABLE user_accessible_assets VALIDATE CONSTRAINT fk_user_accessible_assets_tenant_asset;
