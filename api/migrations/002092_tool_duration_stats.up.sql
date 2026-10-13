-- Learned per-target durations per tenant and tool (research/122, the data
-- loop): each completed scan command folds one sample (its time per target,
-- clamped to the tool's floor and ceiling) into a decayed mean and p95. The
-- platform sizes the next jobs' budgets from them; the target pool sizes
-- claim-time tasks from them.
--
-- Live impact: a new, empty table. Tenant-scoped; removed with its tenant.

CREATE TABLE IF NOT EXISTS tool_duration_stats (
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool        TEXT NOT NULL,
    samples     INTEGER NOT NULL DEFAULT 0,
    mean_ms     DOUBLE PRECISION NOT NULL,
    p95_ms      DOUBLE PRECISION NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, tool),
    CONSTRAINT chk_tool_duration_stats_tool CHECK (length(tool) BETWEEN 1 AND 100),
    CONSTRAINT chk_tool_duration_stats_values CHECK (samples >= 0 AND mean_ms >= 0 AND p95_ms >= 0)
);
