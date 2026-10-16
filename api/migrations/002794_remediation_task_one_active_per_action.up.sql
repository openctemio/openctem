-- One active (open or in progress) task per remediation action, so two CI runs
-- that find the same secret at once cannot each open a rotation task: the
-- second insert hits this index and joins the first task instead.
-- Built concurrently (no write lock on the tasks table); this file runs
-- outside a transaction. If a duplicate active task already exists the build
-- fails and leaves an invalid index: close the extra task and drop the invalid
-- index, then rerun.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_remediation_tasks_one_active_per_action
    ON remediation_tasks (action_id) WHERE state IN ('open', 'in_progress');
