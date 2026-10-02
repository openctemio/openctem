-- Migration 167: Composite indexes supporting blast-radius reverse lookups.
--
-- Powers three new endpoints:
--   GET /api/v1/components/{id}/assets         (component → assets reverse)
--   GET /api/v1/components/{id}/vulnerabilities (component → CVEs)
--   GET /api/v1/vulnerabilities/{id}/affected-assets (CVE → assets)
--
-- The component-CVE direction is already covered by migration 000166.
-- This migration adds the two remaining hot paths.
--
-- NOTE: cannot use CREATE INDEX CONCURRENTLY here — golang-migrate wraps each
-- file in a transaction. See 000165 history for prior incident.

-- (1) asset_components(tenant_id, component_id)
--     Powers ListAssetUsage(): "which assets in tenant X use component Y?".
--     Existing idx_asset_components_tenant covers tenant_id alone but Postgres
--     would still need to scan all of the tenant's components — not great for
--     large tenants (>100k SBOM rows).
--     Partial WHERE component_id IS NOT NULL keeps the index tight (some
--     historical asset_components rows have NULL component_id from earlier
--     ingestion paths).
CREATE INDEX IF NOT EXISTS idx_asset_components_tenant_component
    ON asset_components (tenant_id, component_id)
    WHERE component_id IS NOT NULL;

-- (2) findings(tenant_id, vulnerability_id)
--     Powers ListAffectedAssetsByVulnerabilityID(): "which assets in tenant X
--     are affected by CVE Y?".
--     Existing idx_findings_vulnerability_id is single-column and would force
--     PG to filter by tenant_id after a vuln-wide scan — bad when a popular
--     CVE (e.g. Log4Shell) appears across many tenants.
--     Partial WHERE vulnerability_id IS NOT NULL — secret/misconfig/web3
--     finding types intentionally have NULL vulnerability_id.
CREATE INDEX IF NOT EXISTS idx_findings_tenant_vulnerability
    ON findings (tenant_id, vulnerability_id)
    WHERE vulnerability_id IS NOT NULL;
