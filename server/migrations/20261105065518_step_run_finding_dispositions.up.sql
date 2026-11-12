-- What ingest did with the findings a step run's sensor reported but did not
-- store, so the step reconciles with the findings list: findings_held were
-- held for review (results quarantine), findings_refused were not stored
-- (asset not stored, outside the job's targets, store failed). Constant
-- defaults: no table rewrite.
ALTER TABLE scan_run_steps
    ADD COLUMN IF NOT EXISTS findings_held integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS findings_refused integer NOT NULL DEFAULT 0;
