-- =============================================================================
-- Migration 019: Integrations
-- OpenCTEM OSS Edition
-- =============================================================================

-- Integrations (External connections - SCM, Cloud, Ticketing, Notifications)
CREATE TABLE IF NOT EXISTS integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(30) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    status_message TEXT,
    auth_type VARCHAR(20) DEFAULT 'token',
    base_url VARCHAR(1000),
    credentials_encrypted TEXT,
    last_sync_at TIMESTAMPTZ,
    next_sync_at TIMESTAMPTZ,
    sync_interval_minutes INTEGER DEFAULT 60,
    sync_error TEXT,
    config JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    stats JSONB DEFAULT '{"total_assets": 0, "total_findings": 0}',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_integrations_category CHECK (category IN ('scm', 'security', 'cloud', 'ticketing', 'notification', 'custom')),
    CONSTRAINT chk_integrations_status CHECK (status IN ('pending', 'connected', 'disconnected', 'error', 'expired', 'disabled')),
    CONSTRAINT chk_integrations_auth_type CHECK (auth_type IN ('token', 'oauth', 'api_key', 'basic', 'app', 'iam_role')),
    CONSTRAINT integrations_name_unique UNIQUE (tenant_id, name)
);

COMMENT ON TABLE integrations IS 'External integrations (SCM, Cloud, Ticketing, Notifications)';

-- SCM Integration Extensions
CREATE TABLE IF NOT EXISTS integration_scm_extensions (
    integration_id UUID PRIMARY KEY REFERENCES integrations(id) ON DELETE CASCADE,
    scm_organization VARCHAR(255),
    repository_count INTEGER DEFAULT 0,
    webhook_id VARCHAR(255),
    webhook_secret VARCHAR(255),
    webhook_url VARCHAR(1000),
    default_branch_pattern VARCHAR(100) DEFAULT 'main,master',
    auto_import_repos BOOLEAN DEFAULT FALSE,
    import_private_repos BOOLEAN DEFAULT TRUE,
    import_archived_repos BOOLEAN DEFAULT FALSE,
    include_patterns TEXT[],
    exclude_patterns TEXT[],
    last_repo_sync_at TIMESTAMPTZ
);

COMMENT ON TABLE integration_scm_extensions IS 'SCM-specific integration configuration';

-- Notification Integration Extensions
CREATE TABLE IF NOT EXISTS integration_notification_extensions (
    integration_id UUID PRIMARY KEY REFERENCES integrations(id) ON DELETE CASCADE,
    enabled_severities TEXT[] DEFAULT '{}',
    enabled_event_types TEXT[] DEFAULT '{}',
    message_template TEXT,
    include_details BOOLEAN DEFAULT TRUE,
    min_interval_minutes INTEGER DEFAULT 0
);

COMMENT ON TABLE integration_notification_extensions IS 'Notification-specific integration configuration';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Integrations indexes
CREATE INDEX IF NOT EXISTS idx_integrations_tenant_id ON integrations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_integrations_category ON integrations(category);
CREATE INDEX IF NOT EXISTS idx_integrations_provider ON integrations(provider);
CREATE INDEX IF NOT EXISTS idx_integrations_status ON integrations(status);
CREATE INDEX IF NOT EXISTS idx_integrations_tenant_category ON integrations(tenant_id, category);
CREATE INDEX IF NOT EXISTS idx_integrations_tenant_provider ON integrations(tenant_id, provider);
CREATE INDEX IF NOT EXISTS idx_integrations_created_at ON integrations(created_at DESC);

-- SCM extensions indexes
CREATE INDEX IF NOT EXISTS idx_integration_scm_org ON integration_scm_extensions(scm_organization);
CREATE INDEX IF NOT EXISTS idx_integration_scm_repo_count ON integration_scm_extensions(repository_count);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_integrations_updated_at ON integrations;
CREATE TRIGGER trigger_integrations_updated_at
    BEFORE UPDATE ON integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Foreign Key: assets.integration_id -> integrations.id
-- (Added here since integrations is created in this migration)
-- =============================================================================

DO $$ BEGIN
    ALTER TABLE assets
        ADD CONSTRAINT assets_integration_id_fkey
        FOREIGN KEY (integration_id) REFERENCES integrations(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
