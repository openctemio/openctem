-- =============================================================================
-- Migration 000037: Asset Types (Configurable Asset Type System)
-- OpenCTEM OSS Edition
-- =============================================================================
-- Replaces hardcoded CHECK constraint with a configurable master table.
-- Supports metadata for UI rendering and validation patterns.
-- =============================================================================

-- =============================================================================
-- Asset Type Categories
-- =============================================================================

CREATE TABLE IF NOT EXISTS asset_type_categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50),
    display_order INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Asset Types (Master Table)
-- =============================================================================

CREATE TABLE IF NOT EXISTS asset_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(50) UNIQUE NOT NULL,               -- Used as FK from assets.asset_type
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category_id UUID REFERENCES asset_type_categories(id) ON DELETE SET NULL,
    icon VARCHAR(50),
    color VARCHAR(20),
    display_order INTEGER NOT NULL DEFAULT 0,

    -- Validation Patterns
    pattern_regex VARCHAR(500),                     -- Regex for validating asset identifiers
    pattern_placeholder VARCHAR(200),               -- Placeholder text for input
    pattern_example VARCHAR(200),                   -- Example value

    -- Capabilities
    supports_wildcard BOOLEAN NOT NULL DEFAULT FALSE,
    supports_cidr BOOLEAN NOT NULL DEFAULT FALSE,

    -- Flags
    is_discoverable BOOLEAN NOT NULL DEFAULT TRUE,  -- Can be auto-discovered
    is_scannable BOOLEAN NOT NULL DEFAULT TRUE,     -- Can be scanned
    is_system BOOLEAN NOT NULL DEFAULT TRUE,        -- System-defined (not user-created)
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_asset_type_categories_code ON asset_type_categories(code);
CREATE INDEX IF NOT EXISTS idx_asset_type_categories_active ON asset_type_categories(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_asset_type_categories_order ON asset_type_categories(display_order);

CREATE INDEX IF NOT EXISTS idx_asset_types_code ON asset_types(code);
CREATE INDEX IF NOT EXISTS idx_asset_types_category ON asset_types(category_id);
CREATE INDEX IF NOT EXISTS idx_asset_types_active ON asset_types(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_asset_types_scannable ON asset_types(is_scannable) WHERE is_scannable = TRUE;
CREATE INDEX IF NOT EXISTS idx_asset_types_order ON asset_types(display_order);

-- =============================================================================
-- Triggers
-- =============================================================================

CREATE TRIGGER update_asset_type_categories_updated_at
    BEFORE UPDATE ON asset_type_categories
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_asset_types_updated_at
    BEFORE UPDATE ON asset_types
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Seed Asset Type Categories
-- =============================================================================

INSERT INTO asset_type_categories (code, name, description, icon, display_order) VALUES
('infrastructure', 'Infrastructure', 'Network and infrastructure assets', 'server', 1),
('application', 'Applications', 'Web applications and services', 'globe', 2),
('code', 'Code & Repositories', 'Source code and version control', 'code', 3),
('cloud', 'Cloud Resources', 'Cloud infrastructure and services', 'cloud', 4),
('data', 'Data Assets', 'Databases and data stores', 'database', 5),
('identity', 'Identity & Access', 'User accounts and credentials', 'user', 6),
('other', 'Other', 'Miscellaneous asset types', 'box', 99)
ON CONFLICT (code) DO NOTHING;

-- =============================================================================
-- Seed Asset Types
-- =============================================================================

INSERT INTO asset_types (code, name, description, category_id, icon, color, display_order, pattern_regex, pattern_example, supports_cidr, is_discoverable, is_scannable) VALUES
-- Infrastructure
('domain', 'Domain', 'Root domain name', (SELECT id FROM asset_type_categories WHERE code = 'infrastructure'), 'globe', '#3B82F6', 1, '^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', 'example.com', FALSE, TRUE, TRUE),
('subdomain', 'Subdomain', 'Subdomain', (SELECT id FROM asset_type_categories WHERE code = 'infrastructure'), 'globe', '#60A5FA', 2, '^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', 'api.example.com', FALSE, TRUE, TRUE),
('ip', 'IP Address', 'IPv4 or IPv6 address', (SELECT id FROM asset_type_categories WHERE code = 'infrastructure'), 'server', '#10B981', 3, '^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$', '192.168.1.1', TRUE, TRUE, TRUE),
('ip_range', 'IP Range', 'CIDR notation IP range', (SELECT id FROM asset_type_categories WHERE code = 'infrastructure'), 'server', '#34D399', 4, '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', '192.168.1.0/24', TRUE, TRUE, TRUE),
('port', 'Port', 'Network port', (SELECT id FROM asset_type_categories WHERE code = 'infrastructure'), 'plug', '#6366F1', 5, '^\d{1,5}$', '443', FALSE, TRUE, TRUE),
('network', 'Network', 'Network segment', (SELECT id FROM asset_type_categories WHERE code = 'infrastructure'), 'network', '#8B5CF6', 6, NULL, 'DMZ Network', FALSE, TRUE, FALSE),

-- Applications
('website', 'Website', 'Web application URL', (SELECT id FROM asset_type_categories WHERE code = 'application'), 'globe', '#EC4899', 10, '^https?://', 'https://example.com', FALSE, TRUE, TRUE),
('api', 'API', 'API endpoint', (SELECT id FROM asset_type_categories WHERE code = 'application'), 'zap', '#F59E0B', 11, '^https?://', 'https://api.example.com/v1', FALSE, TRUE, TRUE),
('web_application', 'Web Application', 'Web application', (SELECT id FROM asset_type_categories WHERE code = 'application'), 'layout', '#EF4444', 12, '^https?://', 'https://app.example.com', FALSE, TRUE, TRUE),
('mobile_app', 'Mobile App', 'Mobile application', (SELECT id FROM asset_type_categories WHERE code = 'application'), 'smartphone', '#14B8A6', 13, NULL, 'MyApp iOS', FALSE, FALSE, TRUE),
('service', 'Service', 'Running service', (SELECT id FROM asset_type_categories WHERE code = 'application'), 'activity', '#F97316', 14, NULL, 'PostgreSQL Database', FALSE, TRUE, TRUE),

-- Code & Repositories
('repository', 'Repository', 'Source code repository', (SELECT id FROM asset_type_categories WHERE code = 'code'), 'git-branch', '#A855F7', 20, NULL, 'github.com/org/repo', FALSE, TRUE, TRUE),
('code_artifact', 'Code Artifact', 'Build artifact or package', (SELECT id FROM asset_type_categories WHERE code = 'code'), 'package', '#84CC16', 21, NULL, 'my-app-1.0.0.jar', FALSE, FALSE, TRUE),
('container_image', 'Container Image', 'Docker/OCI container image', (SELECT id FROM asset_type_categories WHERE code = 'code'), 'box', '#06B6D4', 22, NULL, 'registry.io/app:latest', FALSE, TRUE, TRUE),

-- Cloud
('cloud_account', 'Cloud Account', 'Cloud provider account', (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'cloud', '#0EA5E9', 30, NULL, 'AWS Account 123456789012', FALSE, TRUE, FALSE),
('cloud_resource', 'Cloud Resource', 'Cloud resource (VM, bucket, etc.)', (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'cloud', '#38BDF8', 31, NULL, 'arn:aws:s3:::my-bucket', FALSE, TRUE, TRUE),
('kubernetes_cluster', 'Kubernetes Cluster', 'K8s cluster', (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'box', '#7C3AED', 32, NULL, 'prod-cluster', FALSE, TRUE, TRUE),
('kubernetes_namespace', 'K8s Namespace', 'Kubernetes namespace', (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'folder', '#A78BFA', 33, NULL, 'production', FALSE, TRUE, TRUE),
('serverless_function', 'Serverless Function', 'Lambda/Cloud Function', (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'zap', '#FBBF24', 34, NULL, 'my-lambda-function', FALSE, TRUE, TRUE),

-- Data
('database', 'Database', 'Database instance', (SELECT id FROM asset_type_categories WHERE code = 'data'), 'database', '#E11D48', 40, NULL, 'prod-postgresql', FALSE, TRUE, TRUE),
('data_store', 'Data Store', 'Data storage (S3, GCS, etc.)', (SELECT id FROM asset_type_categories WHERE code = 'data'), 'hard-drive', '#BE185D', 41, NULL, 's3://my-bucket', FALSE, TRUE, TRUE),

-- Identity
('user_account', 'User Account', 'User or service account', (SELECT id FROM asset_type_categories WHERE code = 'identity'), 'user', '#4F46E5', 50, NULL, 'admin@example.com', FALSE, TRUE, FALSE),
('credential', 'Credential', 'API key, token, or secret', (SELECT id FROM asset_type_categories WHERE code = 'identity'), 'key', '#DC2626', 51, NULL, 'API_KEY_***', FALSE, FALSE, FALSE),
('ssl_certificate', 'SSL Certificate', 'TLS/SSL certificate', (SELECT id FROM asset_type_categories WHERE code = 'identity'), 'shield', '#059669', 52, NULL, '*.example.com', FALSE, TRUE, FALSE),

-- Other
('host', 'Host', 'Physical or virtual host', (SELECT id FROM asset_type_categories WHERE code = 'other'), 'server', '#64748B', 60, NULL, 'web-server-01', FALSE, TRUE, TRUE),
('iot_device', 'IoT Device', 'Internet of Things device', (SELECT id FROM asset_type_categories WHERE code = 'other'), 'cpu', '#78716C', 61, NULL, 'sensor-001', FALSE, TRUE, TRUE),
('hardware', 'Hardware', 'Physical hardware', (SELECT id FROM asset_type_categories WHERE code = 'other'), 'hard-drive', '#9CA3AF', 62, NULL, 'Firewall-01', FALSE, FALSE, FALSE),
('other', 'Other', 'Other asset type', (SELECT id FROM asset_type_categories WHERE code = 'other'), 'box', '#6B7280', 99, NULL, 'Custom Asset', FALSE, FALSE, FALSE)

ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    category_id = EXCLUDED.category_id,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    display_order = EXCLUDED.display_order,
    pattern_regex = EXCLUDED.pattern_regex,
    pattern_example = EXCLUDED.pattern_example,
    supports_cidr = EXCLUDED.supports_cidr,
    is_discoverable = EXCLUDED.is_discoverable,
    is_scannable = EXCLUDED.is_scannable,
    updated_at = NOW();

-- =============================================================================
-- Add Foreign Key from assets to asset_types (idempotent)
-- =============================================================================

-- Remove old CHECK constraint if exists
ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_type;

-- Add FK constraint (idempotent)
DO $$ BEGIN
    ALTER TABLE assets
        ADD CONSTRAINT fk_assets_asset_type
        FOREIGN KEY (asset_type)
        REFERENCES asset_types(code)
        ON UPDATE CASCADE
        ON DELETE RESTRICT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE asset_type_categories IS 'Categories for grouping asset types (e.g., Infrastructure, Cloud, Code)';
COMMENT ON TABLE asset_types IS 'Master table of asset types with validation patterns and UI metadata';
COMMENT ON COLUMN asset_types.code IS 'Unique code used as FK from assets.asset_type';
COMMENT ON COLUMN asset_types.pattern_regex IS 'Regex for validating asset identifiers of this type';
COMMENT ON COLUMN asset_types.supports_cidr IS 'Whether this type supports CIDR notation (for IP ranges)';
COMMENT ON COLUMN asset_types.is_discoverable IS 'Can be auto-discovered by scanners';
COMMENT ON COLUMN asset_types.is_scannable IS 'Can be scanned for vulnerabilities';
