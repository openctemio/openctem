DELETE FROM ci_alert_state WHERE kind = 'token_refusals';
ALTER TABLE ci_alert_state DROP CONSTRAINT IF EXISTS chk_ci_alert_state_kind;
ALTER TABLE ci_alert_state ADD CONSTRAINT chk_ci_alert_state_kind
    CHECK (kind IN ('schedule_missed', 'coverage_regression', 'gate_failing', 'runner_outdated'));
DELETE FROM event_types WHERE id IN ('ci.break_glass', 'ci.token_refusals');
