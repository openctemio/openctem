-- Reverses 001082_ci_coverage_alerts.up.sql. Findings closed as "source
-- retired" stay closed (their resolution says why); reopen them by hand.

DELETE FROM event_types WHERE id IN ('ci.schedule_missed', 'ci.coverage_regression', 'ci.gate_failing', 'ci.runner_outdated');

ALTER TABLE ci_pipelines DROP CONSTRAINT IF EXISTS chk_ci_pipelines_retire_reason;
ALTER TABLE ci_pipelines
    DROP COLUMN IF EXISTS retire_reason,
    DROP COLUMN IF EXISTS retired_by,
    DROP COLUMN IF EXISTS retired_at;

DROP TABLE IF EXISTS ci_alert_state;
DROP TABLE IF EXISTS ci_coverage_expectations;
