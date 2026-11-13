-- Removing a step from a pipeline no longer deletes the history of its runs.
--
-- step_runs.step_id was ON DELETE CASCADE, and scan_step_outputs cascades
-- from step_runs. Saving a pipeline deleted and re-created every step, so one
-- save erased the step history and chaining inputs of every past and running
-- run of that pipeline. Saves now update steps in place (stable ids); a step
-- that is really removed sets its step runs' step_id to NULL, and the run
-- keeps what it did: step_key, plus the step name and tool copied onto the
-- step run when it was created (backfilled below for existing rows).
--
-- Locks: DROP NOT NULL and the constraint swap take a short ACCESS EXCLUSIVE
-- lock; the new foreign key is added NOT VALID and validated separately
-- (SHARE UPDATE EXCLUSIVE), so the scan of step_runs does not block writes.
-- The backfill touches each existing step run once.

ALTER TABLE step_runs ALTER COLUMN step_id DROP NOT NULL;
ALTER TABLE step_runs
    ADD COLUMN IF NOT EXISTS step_name character varying(255),
    ADD COLUMN IF NOT EXISTS tool character varying(100);

ALTER TABLE step_runs DROP CONSTRAINT IF EXISTS step_runs_step_id_fkey;
ALTER TABLE step_runs
    ADD CONSTRAINT step_runs_step_id_fkey FOREIGN KEY (step_id)
    REFERENCES pipeline_steps(id) ON DELETE SET NULL NOT VALID;
ALTER TABLE step_runs VALIDATE CONSTRAINT step_runs_step_id_fkey;

UPDATE step_runs sr
SET step_name = ps.name, tool = ps.tool
FROM pipeline_steps ps
WHERE ps.id = sr.step_id AND sr.step_name IS NULL;

COMMENT ON COLUMN step_runs.step_id IS 'The pipeline step this run executed; NULL once that step was removed from the pipeline (the run keeps step_key, step_name and tool).';
COMMENT ON COLUMN step_runs.step_name IS 'Name of the step when this step run was created.';
COMMENT ON COLUMN step_runs.tool IS 'Tool the step named when this step run was created (NULL for a capability-only step).';
