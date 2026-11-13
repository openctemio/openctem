-- Whether the scanner still reports a finding (observation.go): present, or
-- stale. A NOT NULL column with a constant default is a catalog change; the
-- CHECK is NOT VALID and validated in finding_status_dimensions_validate.
ALTER TABLE findings ADD COLUMN observation_state varchar(16) NOT NULL DEFAULT 'present';
ALTER TABLE findings ADD CONSTRAINT chk_findings_observation_state
    CHECK (observation_state IN ('present', 'stale')) NOT VALID;
COMMENT ON COLUMN findings.observation_state IS
    'present, or stale: no longer reported and no coverage proof (observation.go); never a status';
