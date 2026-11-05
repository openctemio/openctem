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
    CONSTRAINT pk_web_path_discovery_runs PRIMARY KEY (tenant_id, origin_asset_id),
    CONSTRAINT chk_web_path_discovery_runs_granted CHECK (granted > 0)
);

CREATE INDEX IF NOT EXISTS idx_web_path_discovery_runs_dispatch
    ON web_path_discovery_runs (tenant_id, last_dispatch_at DESC);
CREATE INDEX IF NOT EXISTS idx_web_path_discovery_runs_host_run
    ON web_path_discovery_runs (tenant_id, host, run_id) WHERE run_id IS NOT NULL;

COMMENT ON TABLE web_path_discovery_runs IS
    'Last path discovery dispatch per tenant and web origin, from every caller; the per-origin 30 day floor and the daily request budget read it.';
