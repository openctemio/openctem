-- research/27 P0-3 / research/22 P0-5 (E6), docs/architecture/scan-stages.md:
-- chaining scan stages through the inventory with a gate at every hop.
--
-- Three new tables; nothing existing changes, so the migration is safe on a
-- populated database. Every row carries its tenant, and every reference to a
-- run or an asset includes the tenant (composite foreign keys), so a row can
-- never point across tenants whatever writes it.

-- What each command-bound sensor report wrote, per step run: the assets a
-- stage produced. Written by ingest from the report's server-side binding
-- (never from the report body); read by the hop router after the step
-- finished and its ingest committed.
CREATE TABLE IF NOT EXISTS scan_step_outputs (
    tenant_id   UUID NOT NULL,
    run_id      UUID NOT NULL,
    step_run_id UUID NOT NULL REFERENCES step_runs(id) ON DELETE CASCADE,
    asset_id    UUID NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (step_run_id, asset_id),
    CONSTRAINT fk_scan_step_outputs_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES pipeline_runs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_step_outputs_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_scan_step_outputs_run ON scan_step_outputs (tenant_id, run_id);

-- One row per planned stage of a run: the exactly-once key of planning (a
-- duplicate completion or ingest event plans nothing) and the counts the run
-- view shows ("in N -> planned P, skipped S by reason").
CREATE TABLE IF NOT EXISTS scan_run_stage_plans (
    tenant_id  UUID NOT NULL,
    run_id     UUID NOT NULL,
    stage_key  VARCHAR(100) NOT NULL,
    stage      TEXT NOT NULL DEFAULT '',
    tool       TEXT NOT NULL DEFAULT '',
    tier       SMALLINT NOT NULL DEFAULT 0,
    chained    BOOLEAN NOT NULL DEFAULT FALSE,
    inputs     INT NOT NULL DEFAULT 0,
    planned    INT NOT NULL DEFAULT 0,
    max_hop    SMALLINT NOT NULL DEFAULT 0,
    skipped    JSONB NOT NULL DEFAULT '{}'::jsonb,
    planned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (run_id, stage_key),
    CONSTRAINT fk_scan_run_stage_plans_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES pipeline_runs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_scan_run_stage_plans_counts CHECK (inputs >= 0 AND planned >= 0 AND max_hop >= 0),
    CONSTRAINT chk_scan_run_stage_plans_tier CHECK (tier BETWEEN 0 AND 2),
    CONSTRAINT chk_scan_run_stage_plans_skipped CHECK (jsonb_typeof(skipped) = 'object')
);
CREATE INDEX IF NOT EXISTS ix_scan_run_stage_plans_tenant_run ON scan_run_stage_plans (tenant_id, run_id);

-- Provenance of every target a stage was handed or refused: seed or derived,
-- the parent and hop it came from, and the gate rule that allowed it or the
-- reason it was skipped. One row per (run, stage, target).
CREATE TABLE IF NOT EXISTS scan_run_targets (
    tenant_id        UUID NOT NULL,
    run_id           UUID NOT NULL,
    stage_key        VARCHAR(100) NOT NULL,
    target_key       TEXT NOT NULL,
    asset_id         UUID,
    origin           TEXT NOT NULL,
    parent_asset_id  UUID,
    parent_stage_key VARCHAR(100),
    relation         TEXT,
    hop              SMALLINT NOT NULL DEFAULT 0,
    decision         TEXT NOT NULL,
    reason           TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (run_id, stage_key, target_key),
    CONSTRAINT fk_scan_run_targets_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES pipeline_runs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run_targets_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id),
    CONSTRAINT fk_scan_run_targets_parent FOREIGN KEY (tenant_id, parent_asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE SET NULL (parent_asset_id),
    CONSTRAINT chk_scan_run_targets_origin CHECK (origin IN ('seed', 'derived')),
    CONSTRAINT chk_scan_run_targets_decision CHECK (decision IN ('planned', 'skipped')),
    CONSTRAINT chk_scan_run_targets_hop CHECK (hop >= 0),
    CONSTRAINT chk_scan_run_targets_key CHECK (length(target_key) BETWEEN 1 AND 2048)
);
CREATE INDEX IF NOT EXISTS ix_scan_run_targets_tenant_run ON scan_run_targets (tenant_id, run_id, stage_key);
CREATE INDEX IF NOT EXISTS ix_scan_run_targets_asset ON scan_run_targets (tenant_id, asset_id) WHERE asset_id IS NOT NULL;
