-- =============================================================================
-- Migration 000080: Link Asset Types to Asset Modules
-- =============================================================================
-- Adds explicit mapping between asset_types and their parent module in the
-- modules table. This allows:
-- 1. Filtering asset types based on enabled/disabled modules
-- 2. Consistent UI rendering (disabled module → hidden asset type)
-- 3. Single source of truth for asset type ↔ module relationship
-- =============================================================================

-- Add module_id column to asset_types
ALTER TABLE asset_types ADD COLUMN IF NOT EXISTS module_id VARCHAR(100);

-- Add FK constraint (idempotent)
DO $$ BEGIN
    ALTER TABLE asset_types
        ADD CONSTRAINT fk_asset_types_module
        FOREIGN KEY (module_id)
        REFERENCES modules(id)
        ON UPDATE CASCADE
        ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Create index for quick lookups
CREATE INDEX IF NOT EXISTS idx_asset_types_module_id ON asset_types(module_id) WHERE module_id IS NOT NULL;

-- =============================================================================
-- Seed: Map asset types to their corresponding asset sub-modules
-- =============================================================================

-- Infrastructure
UPDATE asset_types SET module_id = 'assets.domains' WHERE code = 'domain';
UPDATE asset_types SET module_id = 'assets.subdomains' WHERE code = 'subdomain';
UPDATE asset_types SET module_id = 'assets.ips' WHERE code IN ('ip', 'ip_range');
UPDATE asset_types SET module_id = 'assets.ports' WHERE code = 'port';
UPDATE asset_types SET module_id = 'assets.networks' WHERE code = 'network';

-- Applications
UPDATE asset_types SET module_id = 'assets.websites' WHERE code = 'website';
UPDATE asset_types SET module_id = 'assets.apis' WHERE code = 'api';
UPDATE asset_types SET module_id = 'assets.web_apps' WHERE code = 'web_application';
UPDATE asset_types SET module_id = 'assets.mobile_apps' WHERE code = 'mobile_app';
UPDATE asset_types SET module_id = 'assets.services' WHERE code = 'service';

-- Code & Repositories
UPDATE asset_types SET module_id = 'assets.repositories' WHERE code = 'repository';
UPDATE asset_types SET module_id = 'assets.artifacts' WHERE code = 'code_artifact';
UPDATE asset_types SET module_id = 'assets.containers' WHERE code = 'container_image';

-- Cloud
UPDATE asset_types SET module_id = 'assets.cloud_accounts' WHERE code = 'cloud_account';
UPDATE asset_types SET module_id = 'assets.cloud_resources' WHERE code = 'cloud_resource';
UPDATE asset_types SET module_id = 'assets.kubernetes' WHERE code IN ('kubernetes_cluster', 'kubernetes_namespace');
UPDATE asset_types SET module_id = 'assets.serverless' WHERE code = 'serverless_function';
-- assets.compute currently has no dedicated asset type (for future VM/instance types)

-- Data
UPDATE asset_types SET module_id = 'assets.databases' WHERE code = 'database';
UPDATE asset_types SET module_id = 'assets.data_stores' WHERE code = 'data_store';

-- Identity
UPDATE asset_types SET module_id = 'assets.certificates' WHERE code = 'ssl_certificate';
UPDATE asset_types SET module_id = 'assets.credentials' WHERE code = 'credential';

-- Other
UPDATE asset_types SET module_id = 'assets.hosts' WHERE code = 'host';
UPDATE asset_types SET module_id = 'assets.iot' WHERE code = 'iot_device';
UPDATE asset_types SET module_id = 'assets.hardware' WHERE code = 'hardware';
-- 'other' and 'user_account' types don't have a dedicated module

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON COLUMN asset_types.module_id IS 'Links to the modules table. When the module is disabled for a tenant, assets of this type are hidden from UI.';
