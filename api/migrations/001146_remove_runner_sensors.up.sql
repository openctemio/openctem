-- Remove the "runner" sensor type: a sensor API key used from CI. CI jobs
-- authenticate with their CI provider's OIDC identity instead
-- (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).
--
-- Any remaining runner sensor is deleted with its keys and per-sensor rows
-- (every foreign key to sensors cascades or sets NULL: commands, pipeline and
-- step runs, tool executions and scan sessions keep their history with no
-- sensor). Findings never referenced a sensor row. Then the type is no longer
-- accepted.
-- Live impact: runner sensors are rare (one-shot CI keys); the delete is
-- bounded by them, and the CHECK swap scans a small table.

DELETE FROM sensors WHERE type = 'runner';

ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_type;
ALTER TABLE sensors ADD CONSTRAINT chk_sensors_type
    CHECK (type IN ('worker', 'agent', 'scanner', 'collector', 'platform', 'sensor'));
