-- CI run sightings looked up by finding key: the finding re-key moves a
-- key's rows to the new key (finding_rekey.go, moveCIRunFindings) once per
-- re-keyed finding, and finding provenance reads them by key. Without this
-- index each lookup reads the whole table (the primary key leads with
-- run_id).
--
-- CONCURRENTLY keeps the table writable while it builds; it cannot run in a
-- transaction, so this file holds exactly one statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ci_run_findings_tenant_fingerprint
    ON ci_run_findings (tenant_id, fingerprint);
