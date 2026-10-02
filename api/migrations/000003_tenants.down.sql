-- =============================================================================
-- Migration 003: Tenants (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_tenants_updated_at ON tenants;

DROP TABLE IF EXISTS tenant_invitations;
DROP TABLE IF EXISTS tenant_members;
DROP TABLE IF EXISTS tenants;
