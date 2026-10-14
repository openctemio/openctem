-- Asset coverage ledger (docs/rfcs/RFC-093-asset-coverage.md): one row per
-- asset, capability and vantage with the state of that pair (due, queued,
-- covered, failed, blocked, paused, not_applicable), when it was last
-- attempted and last succeeded, the outcome, and when it is due again.
--
-- It replaces two narrower ledgers:
--   * easm_dns_check_state (asset x DNS check): rows move as capability
--     dns.dangling / dns.email;
--   * scan_coverage_state (asset -> last connector dispatch): rows move as
--     capability network_va.connector.
-- Both old tables are dropped after their rows are copied (counts checked).
--
-- Live impact (2026-10-14): ~121 DNS check rows and 0 connector rows are
-- copied; small tables, no long lock. The API must stop during deploy: the
-- old code reads the dropped tables.

CREATE TABLE IF NOT EXISTS asset_coverage (
    tenant_id       uuid         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    asset_id        uuid         NOT NULL,
    capability      varchar(64)  NOT NULL,
    vantage         varchar(64)  NOT NULL DEFAULT '',
    state           varchar(16)  NOT NULL DEFAULT 'due',
    reason          varchar(64)  NOT NULL DEFAULT '',
    priority        smallint     NOT NULL DEFAULT 0,
    next_due_at     timestamptz,
    queued_at       timestamptz,
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    last_outcome    varchar(64)  NOT NULL DEFAULT '',
    last_error      varchar(500) NOT NULL DEFAULT '',
    last_tool       varchar(64)  NOT NULL DEFAULT '',
    last_run_id     uuid,
    fail_streak     smallint     NOT NULL DEFAULT 0,
    change_token    bigint       NOT NULL DEFAULT 0,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_coverage PRIMARY KEY (tenant_id, asset_id, capability, vantage),
    CONSTRAINT fk_asset_coverage_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_coverage_capability
        CHECK (capability ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
    CONSTRAINT chk_asset_coverage_state
        CHECK (state IN ('due', 'queued', 'covered', 'failed', 'blocked', 'paused', 'not_applicable')),
    CONSTRAINT chk_asset_coverage_fail_streak CHECK (fail_streak >= 0)
);

COMMENT ON TABLE asset_coverage IS
    'RFC-093: coverage ledger, one row per asset, capability and vantage: state, last attempt and success, outcome, next due.';

-- The planner reads due and failed pairs per tenant, oldest first.
CREATE INDEX IF NOT EXISTS idx_asset_coverage_due
    ON asset_coverage (tenant_id, next_due_at) WHERE state IN ('due', 'failed');
-- Gap counts and the coverage summary read by capability and state.
CREATE INDEX IF NOT EXISTS idx_asset_coverage_capability_state
    ON asset_coverage (tenant_id, capability, state);

-- DNS checks: dns.<kind>. An outcome the check could not decide is a failed
-- attempt; a name the email check does not apply to is not applicable;
-- anything else is a completed check.
INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, next_due_at,
                            last_attempt_at, last_success_at, last_outcome, last_error,
                            fail_streak, created_at, updated_at)
SELECT s.tenant_id, s.asset_id, 'dns.' || s.check_kind,
       CASE WHEN s.last_outcome = 'unknown' THEN 'failed'
            WHEN s.last_outcome LIKE 'skipped%' THEN 'not_applicable'
            ELSE 'covered' END,
       s.last_checked_at + interval '1 day',
       s.last_checked_at,
       CASE WHEN s.last_outcome = 'unknown' THEN NULL ELSE s.last_checked_at END,
       left(COALESCE(s.last_outcome, ''), 64), left(COALESCE(s.last_error, ''), 500),
       CASE WHEN s.last_outcome = 'unknown' THEN 1 ELSE 0 END,
       now(), now()
FROM easm_dns_check_state s
JOIN assets a ON a.id = s.asset_id AND a.tenant_id = s.tenant_id
ON CONFLICT DO NOTHING;

-- Connector dispatches: network_va.connector, the dispatch time is the
-- last attempt (the connector reports no per-asset outcome).
INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, last_attempt_at,
                            last_success_at, last_outcome, created_at, updated_at)
SELECT c.tenant_id, c.asset_id, 'network_va.connector', 'covered', c.last_dispatched_at,
       c.last_dispatched_at, 'dispatched', c.created_at, c.updated_at
FROM scan_coverage_state c
JOIN assets a ON a.id = c.asset_id AND a.tenant_id = c.tenant_id
ON CONFLICT DO NOTHING;

DO $$
DECLARE
    want bigint;
    got  bigint;
BEGIN
    SELECT (SELECT count(*) FROM easm_dns_check_state s JOIN assets a ON a.id = s.asset_id AND a.tenant_id = s.tenant_id)
         + (SELECT count(*) FROM scan_coverage_state c JOIN assets a ON a.id = c.asset_id AND a.tenant_id = c.tenant_id)
      INTO want;
    SELECT count(*) FROM asset_coverage INTO got;
    IF got <> want THEN
        RAISE EXCEPTION 'asset_coverage copy: % rows, want %', got, want;
    END IF;
END $$;

-- expand-contract-ok: contract step in the same release (owner rule: minimal back-compat, no release wait); the API stops during deploy (upgrade note), and the rows were copied and counted above
DROP TABLE IF EXISTS easm_dns_check_state;
-- expand-contract-ok: same contract step; scan_coverage_state had 0 rows on live and its only reader moved to asset_coverage in this change
DROP TABLE IF EXISTS scan_coverage_state;
