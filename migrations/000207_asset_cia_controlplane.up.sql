-- Migration 000207: CTEM Scoping critical-asset register attributes
-- OpenCTEM OSS Edition — https://ctem.org/docs/stages/ctem-scoping
--
-- Adds the two register attributes the Scoping stage requires that the
-- platform did not yet carry (data classification already existed):
--
--   1. CIA impact rating — impact_confidentiality / impact_integrity /
--      impact_availability, each low | moderate | high. The business
--      impact if the asset is compromised, per CIA leg.
--
--   2. Control-plane dependency flag — is_control_plane on the directed
--      dependency edge, marking an edge as a control plane (IdP/SSO,
--      secrets store, CI/CD, monitoring/SIEM) so scoping a service pulls
--      its control planes into scope.
--
-- All columns are additive and back-compatible: the CIA columns are
-- nullable (NULL = not yet rated) and the control-plane flag defaults to
-- false. No backfill required.

-- CIA impact rating on the asset.
ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS impact_confidentiality VARCHAR(10),
    ADD COLUMN IF NOT EXISTS impact_integrity       VARCHAR(10),
    ADD COLUMN IF NOT EXISTS impact_availability    VARCHAR(10);

-- Validate the CIA ratings (NULL allowed — the attribute is optional).
ALTER TABLE assets
    ADD CONSTRAINT chk_assets_impact_confidentiality
        CHECK (impact_confidentiality IS NULL OR impact_confidentiality IN ('low', 'moderate', 'high')),
    ADD CONSTRAINT chk_assets_impact_integrity
        CHECK (impact_integrity IS NULL OR impact_integrity IN ('low', 'moderate', 'high')),
    ADD CONSTRAINT chk_assets_impact_availability
        CHECK (impact_availability IS NULL OR impact_availability IN ('low', 'moderate', 'high'));

COMMENT ON COLUMN assets.impact_confidentiality IS 'CTEM Scoping CIA impact rating: low|moderate|high (NULL = not rated)';
COMMENT ON COLUMN assets.impact_integrity IS 'CTEM Scoping CIA impact rating: low|moderate|high (NULL = not rated)';
COMMENT ON COLUMN assets.impact_availability IS 'CTEM Scoping CIA impact rating: low|moderate|high (NULL = not rated)';

-- Control-plane dependency flag on the directed relationship edge.
ALTER TABLE asset_relationships
    ADD COLUMN IF NOT EXISTS is_control_plane BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN asset_relationships.is_control_plane IS 'Marks the edge as a control plane (IdP/SSO, secrets store, CI/CD, monitoring/SIEM) for CTEM Scoping';

-- Partial index: control-plane edges are a small, frequently-queried subset
-- (scoping a service walks its control-plane dependencies).
CREATE INDEX IF NOT EXISTS idx_asset_rel_control_plane
    ON asset_relationships(tenant_id, target_asset_id)
    WHERE is_control_plane = true;
