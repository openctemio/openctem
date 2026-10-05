-- CI security signals (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md):
--   ci.break_glass      a break-glass was created, or let a failing run pass
--   ci.token_refusals   a burst of refused CI token exchanges in a tenant
-- and the alert state kind for the burst (one row per tenant while it lasts).
-- Live impact: two catalog rows and a CHECK constraint swap on a small table.

INSERT INTO event_types (id, name, description, category, module_id, default_severity, is_active)
SELECT v.id, v.name, v.description, 'sensor', m.id, v.sev, TRUE
FROM (VALUES
    ('ci.break_glass', 'CI break-glass', 'A break-glass was created, or let a failing CI run pass', 'high'),
    ('ci.token_refusals', 'CI token refusals', 'Many CI token exchanges were refused in a short time', 'high')
) AS v(id, name, description, sev)
LEFT JOIN modules m ON m.id = 'scans'
ON CONFLICT (id) DO NOTHING;

ALTER TABLE ci_alert_state DROP CONSTRAINT IF EXISTS chk_ci_alert_state_kind;
ALTER TABLE ci_alert_state ADD CONSTRAINT chk_ci_alert_state_kind
    CHECK (kind IN ('schedule_missed', 'coverage_regression', 'gate_failing', 'runner_outdated', 'token_refusals'));
