-- Provider shared addresses: the journal of the one-time move job
-- (docs/architecture/provider-address-move.md, runbook in
-- docs/operations/provider-address-move.md).
--
-- An address inside a range a provider publishes for infrastructure many
-- organizations share is not the organization's asset: the names that
-- resolve to it are. The provider-addresses operator command folds the
-- name-to-address links into the names' address history, moves services
-- named by a host name to that name, and archives the provider addresses
-- that carry nothing else. Every change it makes is journaled here so a
-- tenant can be restored exactly.
--
-- provider_address_moves: one row per run of the command for one tenant
-- (a dry run, an apply pass or a restore), with its counts and the position
-- an interrupted apply resumes from.
--
-- provider_address_move_items: one row per address an apply pass changed
-- or skipped, with what it was before (status, attribution) and the full
-- rows of every edge the pass deleted or added and every history row it
-- folded, so a restore puts back exactly that.
--
-- Live impact: two new empty tables and their indexes. No existing table is
-- rewritten or locked.

CREATE TABLE IF NOT EXISTS provider_address_moves (
    id              uuid          NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id       uuid          NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    job_version     integer       NOT NULL,
    dataset_version varchar(64)   NOT NULL,
    mode            varchar(16)   NOT NULL,
    state           varchar(16)   NOT NULL,
    counts          jsonb         NOT NULL DEFAULT '{}'::jsonb,
    cursor_id       uuid,
    notice          jsonb,
    actor           varchar(200)  NOT NULL DEFAULT '',
    error           varchar(1000) NOT NULL DEFAULT '',
    started_at      timestamptz   NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    updated_at      timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT pk_provider_address_moves PRIMARY KEY (id),
    CONSTRAINT ux_provider_address_moves_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT chk_provider_address_moves_mode CHECK (mode IN ('dry_run', 'apply', 'restore')),
    CONSTRAINT chk_provider_address_moves_state CHECK (state IN ('running', 'done', 'failed', 'superseded')),
    CONSTRAINT chk_provider_address_moves_finished CHECK ((state = 'running') = (finished_at IS NULL)),
    CONSTRAINT chk_provider_address_moves_counts CHECK (jsonb_typeof(counts) = 'object'),
    CONSTRAINT chk_provider_address_moves_notice CHECK (notice IS NULL OR jsonb_typeof(notice) = 'object')
);

COMMENT ON TABLE provider_address_moves IS
    'Runs of the provider-addresses command per tenant: dry_run (counts only), apply (folds, relinks, archives) or restore; counts, the resume position of an interrupted run and the one-time tenant notice.';
COMMENT ON COLUMN provider_address_moves.dataset_version IS
    'Version of the published provider range dataset the run classified with; a new dataset version is a new pass.';
COMMENT ON COLUMN provider_address_moves.cursor_id IS
    'Last address asset id (apply) or journal item id (restore) a committed batch handled; an interrupted run resumes after it.';
COMMENT ON COLUMN provider_address_moves.notice IS
    'The one-time tenant notice of the move (counts and its English and Vietnamese text), written once per tenant.';

-- One unfinished apply or restore per tenant: a second runner resumes it.
CREATE UNIQUE INDEX IF NOT EXISTS ux_provider_address_moves_running
    ON provider_address_moves (tenant_id) WHERE state = 'running' AND mode IN ('apply', 'restore');
CREATE INDEX IF NOT EXISTS idx_provider_address_moves_tenant
    ON provider_address_moves (tenant_id, started_at DESC);

CREATE TABLE IF NOT EXISTS provider_address_move_items (
    id                uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id         uuid         NOT NULL,
    move_id           uuid         NOT NULL,
    asset_id          uuid         NOT NULL,
    address           inet         NOT NULL,
    provider          varchar(100) NOT NULL DEFAULT '',
    bucket            varchar(32)  NOT NULL,
    action            varchar(16)  NOT NULL,
    prior_status      varchar(20)  NOT NULL,
    prior_attribution jsonb,
    new_attribution   jsonb,
    edges             jsonb        NOT NULL DEFAULT '[]'::jsonb,
    added_edges       jsonb        NOT NULL DEFAULT '[]'::jsonb,
    folded_keys       jsonb        NOT NULL DEFAULT '[]'::jsonb,
    outcome           varchar(24)  NOT NULL,
    applied_at        timestamptz  NOT NULL DEFAULT now(),
    restored_at       timestamptz,
    revived_at        timestamptz,
    CONSTRAINT pk_provider_address_move_items PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_provider_address_move_items_move FOREIGN KEY (tenant_id, move_id)
        REFERENCES provider_address_moves (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_provider_address_move_items_action CHECK (action IN ('archive', 'keep', 'skip')),
    CONSTRAINT chk_provider_address_move_items_outcome CHECK (outcome IN
        ('applied', 'kept', 'skipped_active_run', 'restored', 'changed', 'revived', 'reclassified')),
    CONSTRAINT chk_provider_address_move_items_json CHECK (jsonb_typeof(edges) = 'array'
        AND jsonb_typeof(added_edges) = 'array' AND jsonb_typeof(folded_keys) = 'array')
);

COMMENT ON TABLE provider_address_move_items IS
    'Journal of the provider-addresses command: per address, its prior status and attribution and the full rows of every edge it deleted or added and every history row it folded, so a restore is exact. asset_id has no foreign key: the journal outlives the asset.';

-- Restore, revive and the next pass read a tenant's items by asset and by outcome.
CREATE INDEX IF NOT EXISTS idx_provider_address_move_items_asset
    ON provider_address_move_items (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_provider_address_move_items_applied
    ON provider_address_move_items (tenant_id, id) WHERE outcome = 'applied';
CREATE INDEX IF NOT EXISTS idx_provider_address_move_items_move
    ON provider_address_move_items (tenant_id, move_id);

-- Row-level security policies in shadow mode, like the other tenant tables.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['provider_address_moves', 'provider_address_move_items'] LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant_isolation', t);
        EXECUTE format($p$CREATE POLICY %I ON %I
            USING ((tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid)
                OR (current_setting('app.is_platform_admin', true) = 'true'))$p$, t || '_tenant_isolation', t);
    END LOOP;
END;
$$;
