-- Path discovery ledger (docs/architecture/web-discovery.md): one row per
-- tenant and web origin holding the last time a path discovery job was
-- dispatched on it, from any caller (the coverage planner, a workflow's
-- paths step, a scan someone started). Every caller checks and claims it, so
-- the per-origin request cap holds per 30 days across all of them, and the
-- organization's daily request budget is the sum of what was granted.
--
-- host and run_id let the per-host budget of one run count across that run's
-- tasks (an origin on another port of the same host shares the host's
-- budget). granted is the request cap signed into the origin's job.
--
-- Live impact: a new, empty table.

CREATE TABLE IF NOT EXISTS web_path_discovery_runs (
    tenant_id        uuid         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    origin_asset_id  uuid         NOT NULL,
    host             varchar(255) NOT NULL,
    run_id           uuid,
    granted          integer      NOT NULL,
    last_dispatch_at timestamptz  NOT NULL DEFAULT now(),
    -- The claiming job and the row it replaced (prev_* null: the origin had
    -- none), so a job refused after the claim, or one that sent no request,
    -- gives the origin back.
    claim_command_id uuid,
    prev_dispatch_at timestamptz,
    prev_run_id      uuid,
    prev_granted     integer,
    prev_host        varchar(255),
    -- The last time a job the sensor reported as empty (no request sent) gave
    -- this origin's claim back: that happens at most once per 30 days.
    release_at       timestamptz,
    CONSTRAINT pk_web_path_discovery_runs PRIMARY KEY (tenant_id, origin_asset_id),
    CONSTRAINT chk_web_path_discovery_runs_granted CHECK (granted > 0),
    CONSTRAINT chk_web_path_discovery_runs_prev CHECK (prev_dispatch_at IS NULL OR (prev_granted > 0 AND prev_host IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_web_path_discovery_runs_dispatch
    ON web_path_discovery_runs (tenant_id, last_dispatch_at DESC);
CREATE INDEX IF NOT EXISTS idx_web_path_discovery_runs_claim
    ON web_path_discovery_runs (tenant_id, claim_command_id) WHERE claim_command_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_web_path_discovery_runs_host_run
    ON web_path_discovery_runs (tenant_id, host, run_id) WHERE run_id IS NOT NULL;

COMMENT ON TABLE web_path_discovery_runs IS
    'Last path discovery dispatch per tenant and web origin, from every caller; the per-origin 30 day floor and the daily request budget read it.';
