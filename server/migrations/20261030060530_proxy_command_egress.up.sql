-- The proxy path the platform handed a job (docs/architecture/sensor-proxies.md,
-- "Task-reported proxy faults"): one row per command and lease epoch, written
-- when an organization sensor claims a scan, retest or validate job that
-- carries a proxy pool, and closed with the job's proxy verdict when its
-- sensor completes or fails it. The verdicts of the last 30 minutes feed the
-- endpoints' health, and the row names the pool and endpoints behind a
-- task's evidence (the command's scan zone is commands.scan_zone_id).
-- A new, empty table: no lock on commands, nothing to backfill.
CREATE TABLE proxy_command_egress (
    command_id    uuid NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    lease_epoch   integer NOT NULL,
    tenant_id     uuid NOT NULL,
    sensor_id     uuid NOT NULL,
    pool_id       uuid NOT NULL,
    pool_revision integer NOT NULL,
    applies_to    text NOT NULL CHECK (applies_to IN ('all', 'public')),
    endpoint_ids  uuid[] NOT NULL,
    assigned_at   timestamptz NOT NULL DEFAULT now(),
    verdict       text CHECK (verdict IN ('ok', 'proxy_fault')),
    proxy_faults  integer NOT NULL DEFAULT 0 CHECK (proxy_faults >= 0),
    verdict_at    timestamptz,
    PRIMARY KEY (command_id, lease_epoch),
    CONSTRAINT fk_proxy_command_egress_pool FOREIGN KEY (tenant_id, pool_id)
        REFERENCES proxy_pools (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_proxy_command_egress_verdict CHECK ((verdict IS NULL) = (verdict_at IS NULL))
);

CREATE INDEX idx_proxy_command_egress_window
    ON proxy_command_egress (tenant_id, pool_id, verdict_at)
    WHERE verdict IS NOT NULL;
