-- A CI run records at most MaxRunFindings sightings for its gate. A run that
-- reported more is marked here, so its verdict fails with a clear reason
-- instead of judging only the first sightings (RFC-051).
-- ADD COLUMN with a constant default does not rewrite the table.
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS findings_over_cap BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN ci_runs.findings_over_cap IS 'The run reported more findings than the gate records (MaxRunFindings); its verdict fails with too_many_findings.';
