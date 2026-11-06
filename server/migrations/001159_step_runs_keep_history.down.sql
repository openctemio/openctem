-- Restore the cascading step_runs.step_id. Step runs whose step was removed
-- (step_id NULL) cannot satisfy NOT NULL again and are deleted, with their
-- scan_step_outputs (which cascade from step_runs).
DELETE FROM step_runs WHERE step_id IS NULL;

ALTER TABLE step_runs DROP CONSTRAINT IF EXISTS step_runs_step_id_fkey;
ALTER TABLE step_runs
    ADD CONSTRAINT step_runs_step_id_fkey FOREIGN KEY (step_id)
    REFERENCES pipeline_steps(id) ON DELETE CASCADE;

ALTER TABLE step_runs
    ALTER COLUMN step_id SET NOT NULL,
    DROP COLUMN IF EXISTS step_name,
    DROP COLUMN IF EXISTS tool;
