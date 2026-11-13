-- The profiles go unless a scan (an automatic enrichment run) still uses
-- them; those scans and their runs are the tenant's history and stay.
DELETE FROM scan_workflow_steps
 WHERE scan_workflow_id IN ('a0000003-0000-0000-0000-000000000001', 'a0000003-0000-0000-0000-000000000002', 'a0000003-0000-0000-0000-000000000003')
   AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.scan_workflow_id = scan_workflow_steps.scan_workflow_id);
DELETE FROM scan_workflows
 WHERE id IN ('a0000003-0000-0000-0000-000000000001', 'a0000003-0000-0000-0000-000000000002', 'a0000003-0000-0000-0000-000000000003')
   AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.scan_workflow_id = scan_workflows.id);
