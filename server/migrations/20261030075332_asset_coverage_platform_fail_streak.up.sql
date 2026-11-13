-- Platform-side failures of a coverage pair (RFC-093, "Platform-side
-- failures"): a failure that is not an observation of the target (no task
-- carried it, the run stalled, the task or tool failed, the sensor's egress,
-- network or proxy failed, the run did not finish it) no longer grows
-- fail_streak, the target's streak that the organization's "keeps failing"
-- alert reads. It grows platform_fail_streak instead: the retry back-off of
-- those failures and the operator's signal. Any observation of the target
-- (success, target-side, edge or rate-limit answer, dead name) resets it.
--
-- Backfill: pairs of the planner whose last outcome is a known platform-side
-- failure move their streak over (their fail_streak counted platform
-- failures as the target's). Platform checks (dns.*) and the connector
-- capability keep their own streak rules and are not touched.
--
-- Live impact: one NOT NULL column with a constant default (catalog-only on
-- PostgreSQL 11+, no rewrite). The backfill updates only failed or paused
-- pairs with such an outcome (about 1,200 rows on the largest install), row
-- locks only.

ALTER TABLE asset_coverage
    ADD COLUMN IF NOT EXISTS platform_fail_streak smallint NOT NULL DEFAULT 0;

ALTER TABLE asset_coverage DROP CONSTRAINT IF EXISTS chk_asset_coverage_platform_fail_streak;
ALTER TABLE asset_coverage
    ADD CONSTRAINT chk_asset_coverage_platform_fail_streak CHECK (platform_fail_streak >= 0) NOT VALID;
ALTER TABLE asset_coverage VALIDATE CONSTRAINT chk_asset_coverage_platform_fail_streak;

UPDATE asset_coverage
SET platform_fail_streak = fail_streak, fail_streak = 0
WHERE fail_streak > 0
  AND state IN ('failed', 'paused')
  AND last_outcome IN ('not_dispatched', 'stalled', 'failed', 'unfinished', 'tool_error', 'egress_refused', 'sensor_network_fault')
  AND capability NOT LIKE 'dns.%'
  AND capability <> 'network_va.connector';

COMMENT ON COLUMN asset_coverage.platform_fail_streak IS
    'Consecutive platform-side failures (check did not run); never a fact about the target. fail_streak counts only observations of the target.';
