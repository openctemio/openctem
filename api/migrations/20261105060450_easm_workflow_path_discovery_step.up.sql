-- Path discovery in the system EASM recon workflows
-- (docs/architecture/web-discovery.md).
--
-- Standard recon, Web and Deep recon gain an optional step that runs
-- enumerate.web_paths on the web services the probe found: candidate paths
-- derived from the organization's own inventory, GET and HEAD only, at most
-- 300 requests per origin (signed into the job's web scope). It starts at
-- Standard depth, waits for its tool (optional: skipped with the reason when
-- no sensor runs it), is delta gated (an origin runs again after 30 days or
-- when its inventory changed) and is skipped while the organization has path
-- discovery turned off (scope settings). Steps name the capability, no tool.
--
-- Only the system templates change; a tenant's copy has its own ids and is
-- never touched (the template-update check offers the new step). Idempotent.

INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, capabilities, config, timeout_seconds, depends_on, condition_type, max_retries, retry_delay_seconds, ui_position_x, ui_position_y, run_policy)
SELECT v.id::uuid, v.workflow::uuid, 'paths', 'Path discovery',
       'Any tool that runs enumerate.web_paths; the platform picks an available one. Checks paths derived from the organization''s own inventory with GET and HEAD only.',
       v.step_order, '{enumerate.web_paths}', '{}', 3600, '{http}', 'always', 1, 60, v.x, 260,
       '{"optional": true, "min_depth": "standard", "depths": {"standard": {"max_targets": 100, "params": {"lists": ["derived"], "max_requests_per_origin": 300}}, "deep": {"max_targets": 200, "params": {"lists": ["derived"], "max_requests_per_origin": 300}}}}'::jsonb
FROM (VALUES
    ('b0000002-0013-0000-0000-000000000010', 'a0000002-0000-0000-0000-000000000013', 10, 1000),
    ('b0000002-0014-0000-0000-000000000005', 'a0000002-0000-0000-0000-000000000014', 5, 400),
    ('b0000002-0015-0000-0000-000000000012', 'a0000002-0000-0000-0000-000000000015', 12, 1000)
) AS v(id, workflow, step_order, x)
WHERE EXISTS (SELECT 1 FROM scan_workflows w WHERE w.id = v.workflow::uuid AND w.is_system_template)
  AND NOT EXISTS (SELECT 1 FROM scan_workflow_steps s WHERE s.scan_workflow_id = v.workflow::uuid AND s.step_key = 'paths')
ON CONFLICT (id) DO NOTHING;
