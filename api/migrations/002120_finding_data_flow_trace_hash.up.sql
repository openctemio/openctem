-- The hash of the trace a finding's data flows were stored from, and the
-- commit that trace was reported for. A re-scan that reports the same trace
-- leaves the rows alone; a changed trace replaces them. Rows stored before
-- have no hash and are replaced once, on the next scan that reports a trace
-- for the finding.
ALTER TABLE finding_data_flows ADD COLUMN IF NOT EXISTS trace_hash varchar(64);
ALTER TABLE finding_data_flows ADD COLUMN IF NOT EXISTS commit_sha varchar(64);

COMMENT ON COLUMN finding_data_flows.trace_hash IS 'SHA-256 (hex) of the normalized trace these rows were stored from; same on every flow of a finding';
COMMENT ON COLUMN finding_data_flows.commit_sha IS 'Commit the trace was reported for: the step lines are that commit''s lines';
