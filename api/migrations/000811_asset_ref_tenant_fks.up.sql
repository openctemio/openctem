-- Composite tenant foreign keys on asset references (research doc 21b, P1-1:
-- the database backstop for C1/C3/C4).
--
-- Step 2 of 3: refuse cross-tenant references from now on.
--
-- Every column below references assets(id) without the tenant, so a row of
-- tenant A could point at an asset of tenant B (findings, exposures and
-- pipeline runs could, through their create endpoints). The application now
-- resolves every written asset id in the caller's tenant; these constraints
-- make the database refuse a cross-tenant reference whatever writes it.
--
-- Pre-flight. Existing cross-tenant rows are never deleted or rewritten
-- here: they are another tenant's data pointing at an asset, and only an
-- operator can decide what each one should become. If any exist, this
-- migration stops with the count per column and changes nothing (the whole
-- file is one transaction). Resolve them with the listing query in
-- docs/deployment/safe-deploy-and-migrations.md ("Asset tenant foreign
-- keys"), then run the migration again.
--
-- NOT VALID: adding the constraints checks new and updated rows only and
-- does not scan the tables, so the brief lock is taken and released at
-- once. 000812 validates the existing rows in its own transaction, under a
-- lock that does not block writes. The single-column foreign keys stay: the
-- composite ones add the tenant to them, with the same ON DELETE action
-- (SET NULL clears only the asset column, never tenant_id).
DO $preflight$
DECLARE
    report text;
BEGIN
    SELECT string_agg(ref || ': ' || n, ', ' ORDER BY ref)
      INTO report
      FROM (
            SELECT 'assets.parent_id' AS ref, COUNT(*) AS n FROM assets x JOIN assets a ON a.id = x.parent_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'asset_access_grants.asset_id' AS ref, COUNT(*) AS n FROM asset_access_grants x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'asset_attributions.asset_id' AS ref, COUNT(*) AS n FROM asset_attributions x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'asset_components.asset_id' AS ref, COUNT(*) AS n FROM asset_components x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'asset_identifiers.asset_id' AS ref, COUNT(*) AS n FROM asset_identifiers x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'asset_relationships.source_asset_id' AS ref, COUNT(*) AS n FROM asset_relationships x JOIN assets a ON a.id = x.source_asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'asset_relationships.target_asset_id' AS ref, COUNT(*) AS n FROM asset_relationships x JOIN assets a ON a.id = x.target_asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'asset_services.asset_id' AS ref, COUNT(*) AS n FROM asset_services x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'asset_state_history.asset_id' AS ref, COUNT(*) AS n FROM asset_state_history x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'asset_type_reclassifications.asset_id' AS ref, COUNT(*) AS n FROM asset_type_reclassifications x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'business_service_assets.asset_id' AS ref, COUNT(*) AS n FROM business_service_assets x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'business_unit_assets.asset_id' AS ref, COUNT(*) AS n FROM business_unit_assets x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'easm_dns_check_state.asset_id' AS ref, COUNT(*) AS n FROM easm_dns_check_state x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'easm_evidence.asset_id' AS ref, COUNT(*) AS n FROM easm_evidence x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'exposure_events.asset_id' AS ref, COUNT(*) AS n FROM exposure_events x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'exposures.asset_id' AS ref, COUNT(*) AS n FROM exposures x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'finding_retests.asset_id' AS ref, COUNT(*) AS n FROM finding_retests x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'findings.asset_id' AS ref, COUNT(*) AS n FROM findings x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'pipeline_runs.asset_id' AS ref, COUNT(*) AS n FROM pipeline_runs x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'relationship_suggestions.source_asset_id' AS ref, COUNT(*) AS n FROM relationship_suggestions x JOIN assets a ON a.id = x.source_asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'relationship_suggestions.target_asset_id' AS ref, COUNT(*) AS n FROM relationship_suggestions x JOIN assets a ON a.id = x.target_asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'runtime_telemetry_events.endpoint_asset_id' AS ref, COUNT(*) AS n FROM runtime_telemetry_events x JOIN assets a ON a.id = x.endpoint_asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'scan_coverage_state.asset_id' AS ref, COUNT(*) AS n FROM scan_coverage_state x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'scan_sessions.asset_id' AS ref, COUNT(*) AS n FROM scan_sessions x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'sla_policies.asset_id' AS ref, COUNT(*) AS n FROM sla_policies x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'suppression_rules.asset_id' AS ref, COUNT(*) AS n FROM suppression_rules x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
            UNION ALL SELECT 'user_accessible_assets.asset_id' AS ref, COUNT(*) AS n FROM user_accessible_assets x JOIN assets a ON a.id = x.asset_id WHERE x.tenant_id <> a.tenant_id
      ) counts
     WHERE n > 0;
    IF report IS NOT NULL THEN
        RAISE EXCEPTION 'cross-tenant asset references found, migration not applied: %', report
            USING HINT = 'Nothing was changed. List the rows with the query in docs/deployment/safe-deploy-and-migrations.md (Asset tenant foreign keys), repoint or remove each one, then migrate again.';
    END IF;
END
$preflight$;

ALTER TABLE assets
    ADD CONSTRAINT fk_assets_tenant_parent
    FOREIGN KEY (tenant_id, parent_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (parent_id)
    NOT VALID;

ALTER TABLE asset_access_grants
    ADD CONSTRAINT fk_asset_access_grants_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE asset_attributions
    ADD CONSTRAINT fk_asset_attributions_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE asset_components
    ADD CONSTRAINT fk_asset_components_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE asset_identifiers
    ADD CONSTRAINT fk_asset_identifiers_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE asset_relationships
    ADD CONSTRAINT fk_asset_relationships_tenant_source_asset
    FOREIGN KEY (tenant_id, source_asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE asset_relationships
    ADD CONSTRAINT fk_asset_relationships_tenant_target_asset
    FOREIGN KEY (tenant_id, target_asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE asset_services
    ADD CONSTRAINT fk_asset_services_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE asset_state_history
    ADD CONSTRAINT fk_asset_state_history_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE asset_type_reclassifications
    ADD CONSTRAINT fk_asset_type_reclassifications_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE business_service_assets
    ADD CONSTRAINT fk_business_service_assets_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE business_unit_assets
    ADD CONSTRAINT fk_business_unit_assets_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE easm_dns_check_state
    ADD CONSTRAINT fk_easm_dns_check_state_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE easm_evidence
    ADD CONSTRAINT fk_easm_evidence_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE exposure_events
    ADD CONSTRAINT fk_exposure_events_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id)
    NOT VALID;

ALTER TABLE exposures
    ADD CONSTRAINT fk_exposures_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE finding_retests
    ADD CONSTRAINT fk_finding_retests_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id)
    NOT VALID;

ALTER TABLE findings
    ADD CONSTRAINT fk_findings_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE NO ACTION
    NOT VALID;

ALTER TABLE pipeline_runs
    ADD CONSTRAINT fk_pipeline_runs_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id)
    NOT VALID;

ALTER TABLE relationship_suggestions
    ADD CONSTRAINT fk_relationship_suggestions_tenant_source_asset
    FOREIGN KEY (tenant_id, source_asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE relationship_suggestions
    ADD CONSTRAINT fk_relationship_suggestions_tenant_target_asset
    FOREIGN KEY (tenant_id, target_asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE runtime_telemetry_events
    ADD CONSTRAINT fk_runtime_telemetry_events_tenant_endpoint_asset
    FOREIGN KEY (tenant_id, endpoint_asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (endpoint_asset_id)
    NOT VALID;

ALTER TABLE scan_coverage_state
    ADD CONSTRAINT fk_scan_coverage_state_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE scan_sessions
    ADD CONSTRAINT fk_scan_sessions_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id)
    NOT VALID;

ALTER TABLE sla_policies
    ADD CONSTRAINT fk_sla_policies_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE suppression_rules
    ADD CONSTRAINT fk_suppression_rules_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;

ALTER TABLE user_accessible_assets
    ADD CONSTRAINT fk_user_accessible_assets_tenant_asset
    FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
    NOT VALID;
