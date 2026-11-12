-- The Network starter workflow finds live hosts first (RFC-088 step 6;
-- docs/architecture/scan-stages.md): a Host discovery step (discover.hosts)
-- comes before the port scan, which now depends on it. A scan whose address
-- ranges are scanned live hosts first (cidr_mode liveness) sends the ranges
-- to Host discovery only; the port scan and the steps after it get the live
-- hosts it found plus the addresses the inventory knows inside the ranges.
-- A run of names or single addresses settles Host discovery without a
-- command and the port scan runs on its own targets as before.
--
-- Only the system template changes. Copies a tenant already made of it are
-- theirs and stay as they are.
--
-- Live impact: one row inserted and four rows updated in
-- scan_workflow_steps; no lock beyond those rows.

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y)
VALUES ('b0000002-0004-0000-0000-000000000004', 'a0000002-0000-0000-0000-000000000004', 'hosts', 'Host discovery', 'Any tool that runs discover.hosts: the live addresses of the address ranges, found with light probes before the port scan. The platform picks an available one.', 1, '{discover.hosts}', '{}', 3600, '{}', 'always', 1, 60, 100, 120)
ON CONFLICT (id) DO NOTHING;

UPDATE scan_workflow_steps SET step_order = 2, depends_on = '{hosts}', ui_position_x = 400
WHERE id = 'b0000002-0004-0000-0000-000000000001' AND scan_workflow_id = 'a0000002-0000-0000-0000-000000000004';
UPDATE scan_workflow_steps SET step_order = 3, ui_position_x = 700
WHERE id = 'b0000002-0004-0000-0000-000000000002' AND scan_workflow_id = 'a0000002-0000-0000-0000-000000000004';
UPDATE scan_workflow_steps SET step_order = 4, ui_position_x = 1000
WHERE id = 'b0000002-0004-0000-0000-000000000003' AND scan_workflow_id = 'a0000002-0000-0000-0000-000000000004';

UPDATE scan_workflows
SET description = 'Find the live hosts of address ranges, scan addresses and hosts for open ports, probe the web services and run non-intrusive vulnerability templates on the services found.'
WHERE id = 'a0000002-0000-0000-0000-000000000004';
