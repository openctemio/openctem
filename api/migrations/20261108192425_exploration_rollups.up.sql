-- Precomputed exploration figures (docs/architecture/exploration.md,
-- "Rollups"): one row per exploration, written by the exploration controller
-- after each pass and by Refresh now, read by the Exploration page and the
-- dashboard. Derived data only; rebuilt from the leads at any time.
CREATE TABLE IF NOT EXISTS exploration_rollups (
    tenant_id              uuid        NOT NULL,
    exploration_id         uuid        NOT NULL,
    open_leads             integer     NOT NULL DEFAULT 0,
    awaiting_approval      integer     NOT NULL DEFAULT 0,
    running                integer     NOT NULL DEFAULT 0,
    blocked                integer     NOT NULL DEFAULT 0,
    done_30d               integer     NOT NULL DEFAULT 0,
    proven_30d             integer     NOT NULL DEFAULT 0,
    refuted_30d            integer     NOT NULL DEFAULT 0,
    dispatches_30d         integer     NOT NULL DEFAULT 0,
    rule_share             real,
    median_verdict_seconds integer,
    last_step_at           timestamptz,
    computed_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT exploration_rollups_pkey PRIMARY KEY (tenant_id, exploration_id),
    CONSTRAINT fk_exploration_rollups_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_exploration_rollups_exploration FOREIGN KEY (tenant_id, exploration_id)
        REFERENCES explorations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_exploration_rollups_counts CHECK (
        open_leads >= 0 AND awaiting_approval >= 0 AND running >= 0 AND blocked >= 0 AND done_30d >= 0
        AND proven_30d >= 0 AND refuted_30d >= 0 AND dispatches_30d >= 0),
    CONSTRAINT chk_exploration_rollups_share CHECK (rule_share IS NULL OR rule_share BETWEEN 0 AND 1)
);

COMMENT ON TABLE exploration_rollups IS
    'Precomputed figures of one exploration (organization-wide): live leads by state, settled leads and verdicts of the last 30 days, dispatches, the share of leads opened by rules, the median time to a verdict and the last step. Derived from the leads; never the source of truth.';

DROP POLICY IF EXISTS exploration_rollups_tenant_isolation ON exploration_rollups;
CREATE POLICY exploration_rollups_tenant_isolation ON exploration_rollups
    USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
        OR (current_setting('app.is_platform_admin', true) = 'true'));
