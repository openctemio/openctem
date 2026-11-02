-- Retire the system workflow "Quick Scan Template".
--
-- Its only step names the bare scan capability, which no tool provides, so the
-- workflow list showed it as "Not available" and it could not be run. Quick and
-- single scans do not use it as a workflow: they only anchor their run to this
-- row (scan_runs.scan_workflow_id), and that path does not read is_active.
-- Deactivated, not deleted, so those runs keep their parent; the active list
-- already hides an inactive system template. No replacement workflow.
UPDATE scan_workflows
SET is_active = false, updated_at = now()
WHERE id = '00000000-0000-0000-0000-000000000001' AND is_system_template AND is_active;
