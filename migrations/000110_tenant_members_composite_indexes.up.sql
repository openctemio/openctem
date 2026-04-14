-- =============================================================================
-- Migration 110: Composite indexes on tenant_members
--
-- After migration 109 added the `status` column, two query patterns
-- became hot paths that the existing single-column indexes don't
-- cover well:
--
--   1. `WHERE user_id = $1 AND status = 'active'`
--      Used by GetUserMemberships() — called on every login, every
--      refresh-token exchange, and the JWT-tenant membership middleware
--      runs for every request to a /api/v1/me/* or /api/v1/notifications
--      style endpoint. With only `idx_tenant_members_user_id` Postgres
--      reads all of the user's memberships and filters in memory; the
--      composite index lets it filter in the index.
--
--   2. `WHERE tenant_id = $1 AND status = 'active'` and the COUNT() in
--      GetMemberStats. Without a composite index Postgres has to read
--      every member row of the tenant; with one it can answer the
--      count via an index-only scan.
--
-- We do NOT add `(user_id, tenant_id)` because the existing UNIQUE
-- constraint `tenant_members_user_tenant_unique` already creates an
-- equivalent index.
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_tenant_members_user_status
    ON tenant_members (user_id, status);

CREATE INDEX IF NOT EXISTS idx_tenant_members_tenant_status
    ON tenant_members (tenant_id, status);

COMMENT ON INDEX idx_tenant_members_user_status IS
    'Speeds up GetUserMemberships filter (WHERE user_id=$1 AND status=$2)';
COMMENT ON INDEX idx_tenant_members_tenant_status IS
    'Speeds up per-tenant active-member counts in GetMemberStats';
