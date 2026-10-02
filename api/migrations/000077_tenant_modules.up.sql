-- Tenant Module Management
-- Allows tenant admins to enable/disable optional modules per tenant.
-- Core modules (dashboard, assets, findings, scans, team, roles, audit, settings)
-- are always enabled and cannot be disabled.

-- Add is_core column to modules table
ALTER TABLE modules ADD COLUMN IF NOT EXISTS is_core BOOLEAN NOT NULL DEFAULT FALSE;

-- Mark core modules (essential for platform operation)
UPDATE modules SET is_core = TRUE WHERE id IN (
    'dashboard', 'assets', 'findings', 'scans',
    'team', 'roles', 'audit', 'settings'
);

-- Per-tenant module configuration
CREATE TABLE IF NOT EXISTS tenant_modules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    module_id VARCHAR(50) NOT NULL REFERENCES modules(id),
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    enabled_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, module_id)
);

CREATE INDEX idx_tenant_modules_tenant ON tenant_modules(tenant_id);
CREATE INDEX idx_tenant_modules_enabled ON tenant_modules(tenant_id, is_enabled);
