-- RFC-021 Phase-1a: per-user customizable dashboards. Each user owns 0..N saved
-- dashboards (a name + a JSON widget layout). Everything is self-scoped: every
-- read and write is filtered by (tenant_id, user_id), so a user only ever sees
-- or edits their own dashboards. Tenant-scoped like every other runtime table
-- (FK to tenants for cascade cleanup on tenant deletion; FK to users so a
-- deleted user's saved dashboards go with them).
CREATE TABLE IF NOT EXISTS user_dashboards (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT false,
    layout     JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Primary access path: list/scoped lookups for one user.
CREATE INDEX IF NOT EXISTS idx_user_dashboards_tenant_user
    ON user_dashboards (tenant_id, user_id);

-- A user cannot have two dashboards with the same name.
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_dashboards_tenant_user_name
    ON user_dashboards (tenant_id, user_id, name);

-- At most one default dashboard per user (partial unique index).
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_dashboards_one_default
    ON user_dashboards (tenant_id, user_id) WHERE is_default;
