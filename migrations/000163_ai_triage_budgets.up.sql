-- Per-tenant AI-triage token budget (RFC-008 Phase 1).
--
-- One row per (tenant_id, period_start). period_start is UTC-
-- normalised to the first instant of the billing month. The service
-- upserts on access; history is preserved by never updating an old
-- period_end'd row.
--
-- token_limit = 0 OR NULL means "unlimited" (back-compat for tenants
-- who existed before the budget feature shipped). tokens_used is a
-- running counter updated on each triage completion.
--
-- thresholds (warn / block) are percent-of-limit. NULLs default to
-- 80 / 100 in the service layer. Soft warnings fire at crossing of
-- warn_threshold_pct; block fires when tokens_used >= limit *
-- block_threshold_pct / 100.

CREATE TABLE IF NOT EXISTS ai_triage_budgets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Period window: first instant of the month in UTC. Exactly one
    -- row per (tenant_id, period_start).
    period_start TIMESTAMPTZ NOT NULL,
    period_end   TIMESTAMPTZ NOT NULL,

    -- Budget
    token_limit      BIGINT NOT NULL DEFAULT 0,         -- 0 = unlimited
    tokens_used      BIGINT NOT NULL DEFAULT 0,

    -- Optional per-row overrides. NULL = service defaults.
    warn_threshold_pct  INT,
    block_threshold_pct INT,

    -- Soft notification state — records at which absolute used-value
    -- we last emitted a warn/block event so retries are idempotent
    -- and we don't spam the tenant on every triage after crossing
    -- a threshold.
    last_warn_sent_used  BIGINT NOT NULL DEFAULT -1,
    last_block_sent_used BIGINT NOT NULL DEFAULT -1,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (token_limit  >= 0),
    CHECK (tokens_used  >= 0),
    CHECK (warn_threshold_pct  IS NULL OR (warn_threshold_pct  BETWEEN 0 AND 100)),
    CHECK (block_threshold_pct IS NULL OR (block_threshold_pct BETWEEN 0 AND 100)),
    CHECK (period_end > period_start),

    UNIQUE (tenant_id, period_start)
);

CREATE INDEX IF NOT EXISTS idx_ai_triage_budgets_tenant_period
    ON ai_triage_budgets(tenant_id, period_start DESC);

COMMENT ON TABLE ai_triage_budgets IS
    'Per-tenant AI-triage monthly token budget. See RFC-008.';
COMMENT ON COLUMN ai_triage_budgets.token_limit IS
    '0 = unlimited (back-compat).';
COMMENT ON COLUMN ai_triage_budgets.last_warn_sent_used IS
    'tokens_used value at which the warn notification was last emitted; -1 = never.';
