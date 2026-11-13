-- Automations go back to "what is stored is what runs". A live automation's
-- draft may differ from its published version; the draft is what the old
-- engine runs. Run step history keeps rows whose node no longer exists, so
-- the foreign key is restored NOT VALID (it applies to new rows only).
ALTER TABLE automation_runs DROP CONSTRAINT IF EXISTS chk_automation_runs_mode;
ALTER TABLE automation_runs DROP COLUMN IF EXISTS version_id;
ALTER TABLE automation_runs DROP COLUMN IF EXISTS mode;

ALTER TABLE automations DROP CONSTRAINT IF EXISTS chk_automations_mode;
ALTER TABLE automations DROP COLUMN IF EXISTS published_version_id;
ALTER TABLE automations DROP COLUMN IF EXISTS mode;

DROP TABLE IF EXISTS automation_versions;

ALTER TABLE automation_run_steps DROP CONSTRAINT IF EXISTS automation_run_steps_node_id_fkey;
ALTER TABLE automation_run_steps
    ADD CONSTRAINT automation_run_steps_node_id_fkey FOREIGN KEY (node_id)
    REFERENCES automation_nodes (id) ON DELETE CASCADE NOT VALID;
