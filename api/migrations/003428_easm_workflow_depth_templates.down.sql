-- Reverse of the EASM workflow depth and built-in recon workflows.
-- Tenant copies of the five workflows keep their steps; their run policies
-- go with the column.

-- A workflow a scan or a run still references is kept, with its steps.
DELETE FROM scan_workflow_steps st
WHERE st.scan_workflow_id IN (
    'a0000002-0000-0000-0000-000000000012',
    'a0000002-0000-0000-0000-000000000013',
    'a0000002-0000-0000-0000-000000000014',
    'a0000002-0000-0000-0000-000000000015')
  AND NOT EXISTS (SELECT 1 FROM scan_runs r WHERE r.scan_workflow_id = st.scan_workflow_id)
  AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.scan_workflow_id = st.scan_workflow_id);
DELETE FROM scan_workflows w
WHERE w.id IN (
    'a0000002-0000-0000-0000-000000000012',
    'a0000002-0000-0000-0000-000000000013',
    'a0000002-0000-0000-0000-000000000014',
    'a0000002-0000-0000-0000-000000000015')
  AND NOT EXISTS (SELECT 1 FROM scan_runs r WHERE r.scan_workflow_id = w.id)
  AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.scan_workflow_id = w.id);

UPDATE scan_workflows SET is_active = true, updated_at = now()
WHERE id IN ('a0000002-0000-0000-0000-000000000001', 'a0000002-0000-0000-0000-000000000002', 'a0000002-0000-0000-0000-000000000003');
UPDATE scan_workflows
SET settings = settings - 'delta_gating' - 'continue_on_failed_dependency',
    tags = array_remove(tags, 'easm-recon'),
    version = GREATEST(version - 1, 1), updated_at = now()
WHERE id = 'a0000002-0000-0000-0000-000000000006';

ALTER TABLE scan_workflow_steps DROP CONSTRAINT IF EXISTS chk_scan_workflow_steps_run_policy;
ALTER TABLE scan_workflow_steps DROP COLUMN IF EXISTS run_policy;
ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_depth;
ALTER TABLE scans DROP COLUMN IF EXISTS depth;
