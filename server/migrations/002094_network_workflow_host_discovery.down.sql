-- The Network starter workflow starts with the port scan again.

UPDATE scan_workflow_steps SET step_order = 1, depends_on = '{}', ui_position_x = 100
WHERE id = 'b0000002-0004-0000-0000-000000000001' AND scan_workflow_id = 'a0000002-0000-0000-0000-000000000004';
UPDATE scan_workflow_steps SET step_order = 2, ui_position_x = 400
WHERE id = 'b0000002-0004-0000-0000-000000000002' AND scan_workflow_id = 'a0000002-0000-0000-0000-000000000004';
UPDATE scan_workflow_steps SET step_order = 3, ui_position_x = 700
WHERE id = 'b0000002-0004-0000-0000-000000000003' AND scan_workflow_id = 'a0000002-0000-0000-0000-000000000004';

DELETE FROM scan_workflow_steps WHERE id = 'b0000002-0004-0000-0000-000000000004';

UPDATE scan_workflows
SET description = 'Scan addresses and hosts for open ports, probe the web services and run non-intrusive vulnerability templates on the services found.'
WHERE id = 'a0000002-0000-0000-0000-000000000004';
