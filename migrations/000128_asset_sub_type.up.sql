-- =============================================================================
-- Migration 000128: Add sub_type column (Phase 1 — SAFE, no type changes)
-- =============================================================================
-- ONLY adds sub_type column and backfills from current type.
-- Does NOT change asset_type values. Zero risk of breaking anything.
-- Rollback: DROP COLUMN sub_type
-- =============================================================================

-- Add sub_type column
ALTER TABLE assets ADD COLUMN IF NOT EXISTS sub_type VARCHAR(50);

CREATE INDEX IF NOT EXISTS idx_assets_sub_type
    ON assets(tenant_id, asset_type, sub_type) WHERE sub_type IS NOT NULL;

-- Backfill: set sub_type = asset_type for types that will eventually consolidate.
-- This preserves the original identity for future Phase 3 migration.
-- asset_type column is NOT changed.

-- Network devices: sub_type = device type
UPDATE assets SET sub_type = 'firewall'      WHERE asset_type = 'firewall'      AND sub_type IS NULL;
UPDATE assets SET sub_type = 'load_balancer' WHERE asset_type = 'load_balancer' AND sub_type IS NULL;

-- Network devices from hosts tagged network-device: sub_type = device_role
UPDATE assets SET sub_type = properties->>'device_role'
    WHERE asset_type = 'host'
    AND 'network-device' = ANY(tags)
    AND properties->>'device_role' IS NOT NULL
    AND sub_type IS NULL;

-- Applications: sub_type = app type
UPDATE assets SET sub_type = 'website'         WHERE asset_type = 'website'         AND sub_type IS NULL;
UPDATE assets SET sub_type = 'web_application' WHERE asset_type = 'web_application' AND sub_type IS NULL;
UPDATE assets SET sub_type = 'api'             WHERE asset_type = 'api'             AND sub_type IS NULL;
UPDATE assets SET sub_type = 'mobile_app'      WHERE asset_type = 'mobile_app'      AND sub_type IS NULL;

-- Cloud compute: sub_type = compute variant
UPDATE assets SET sub_type = 'compute'    WHERE asset_type = 'compute'    AND sub_type IS NULL;
UPDATE assets SET sub_type = 'serverless' WHERE asset_type = 'serverless' AND sub_type IS NULL;

-- Cloud network: sub_type = network construct
UPDATE assets SET sub_type = 'vpc'    WHERE asset_type = 'vpc'    AND sub_type IS NULL;
UPDATE assets SET sub_type = 'subnet' WHERE asset_type = 'subnet' AND sub_type IS NULL;

-- Identity: sub_type = identity type
UPDATE assets SET sub_type = 'iam_user'        WHERE asset_type = 'iam_user'        AND sub_type IS NULL;
UPDATE assets SET sub_type = 'iam_role'        WHERE asset_type = 'iam_role'        AND sub_type IS NULL;
UPDATE assets SET sub_type = 'service_account' WHERE asset_type = 'service_account' AND sub_type IS NULL;

-- Storage: sub_type = storage variant
UPDATE assets SET sub_type = 's3_bucket'          WHERE asset_type = 's3_bucket'          AND sub_type IS NULL;
UPDATE assets SET sub_type = 'container_registry' WHERE asset_type = 'container_registry' AND sub_type IS NULL;
UPDATE assets SET sub_type = 'data_store'         WHERE asset_type = 'data_store'         AND sub_type IS NULL;

-- Kubernetes: sub_type = k8s object
UPDATE assets SET sub_type = 'cluster'   WHERE asset_type = 'kubernetes_cluster'   AND sub_type IS NULL;
UPDATE assets SET sub_type = 'namespace' WHERE asset_type = 'kubernetes_namespace' AND sub_type IS NULL;

-- Recon artifacts: sub_type = discovery type
UPDATE assets SET sub_type = 'http'           WHERE asset_type = 'http_service'   AND sub_type IS NULL;
UPDATE assets SET sub_type = 'open_port'      WHERE asset_type = 'open_port'      AND sub_type IS NULL;
UPDATE assets SET sub_type = 'discovered_url' WHERE asset_type = 'discovered_url' AND sub_type IS NULL;
