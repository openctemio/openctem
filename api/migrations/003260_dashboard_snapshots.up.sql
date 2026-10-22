-- Dashboard snapshots, the refresher and Refresh now
-- (docs/architecture/dashboards.md, "Snapshots and refresh").
--
-- One stored result per dashboard: opening a dashboard reads it instead of
-- computing. A personal snapshot records the scope it was computed for
-- (scope_key) and is never served once the owner's scope changed; an
-- organization snapshot holds organization-wide figures. The tables are new
-- and empty: safe on a populated database.

CREATE TABLE IF NOT EXISTS dash_snapshots (
    tenant_id       uuid        NOT NULL,
    dashboard_id    uuid        NOT NULL,
    kind            varchar(16) NOT NULL,
    -- The owner of a personal dashboard; NULL for an organization dashboard.
    owner_user_id   uuid,
    scope_key       text        NOT NULL,
    layout_hash     text        NOT NULL,
    data            jsonb       NOT NULL,
    computed_at     timestamptz NOT NULL,
    duration_ms     integer     NOT NULL DEFAULT 0,
    next_refresh_at timestamptz,
    last_error      varchar(32),
    failed_at       timestamptz,
    viewed_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_dash_snapshots PRIMARY KEY (tenant_id, dashboard_id),
    CONSTRAINT fk_dash_snapshots_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_dash_snapshots_dashboard FOREIGN KEY (dashboard_id) REFERENCES user_dashboards (id) ON DELETE CASCADE,
    CONSTRAINT chk_dash_snapshots_kind CHECK (kind IN ('personal', 'organization')),
    CONSTRAINT chk_dash_snapshots_owner CHECK ((kind = 'personal') = (owner_user_id IS NOT NULL))
);
COMMENT ON TABLE dash_snapshots IS
    'Stored widget results of one dashboard. Personal: computed for the owner''s data scope, scope_key fingerprints that scope and a snapshot of another scope is never served. Organization: organization-wide figures; list rows keep their pentest campaign and are filtered per viewer on read.';

CREATE INDEX IF NOT EXISTS idx_dash_snapshots_due ON dash_snapshots (next_refresh_at)
    WHERE next_refresh_at IS NOT NULL;

-- Refresh now requests, for the budget: one per minute per person and
-- dashboard, 30 per hour per organization. Pruned by the refresher.
CREATE TABLE IF NOT EXISTS dash_refresh_requests (
    tenant_id    uuid        NOT NULL,
    dashboard_id uuid        NOT NULL,
    user_id      uuid        NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_dash_refresh_requests_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);
COMMENT ON TABLE dash_refresh_requests IS
    'Accepted Refresh now requests (dashboard snapshots), counted against the per-person and per-organization budget; rows older than a day are pruned.';

CREATE INDEX IF NOT EXISTS idx_dash_refresh_requests_tenant ON dash_refresh_requests (tenant_id, requested_at);
CREATE INDEX IF NOT EXISTS idx_dash_refresh_requests_time ON dash_refresh_requests (requested_at);

-- Row-level security policies in shadow mode, like the other tenant tables.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['dash_snapshots', 'dash_refresh_requests'] LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format($p$CREATE POLICY %I ON %I
            USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
                OR (current_setting('app.is_platform_admin', true) = 'true'))$p$, t || '_tenant_isolation', t);
    END LOOP;
END;
$$;
