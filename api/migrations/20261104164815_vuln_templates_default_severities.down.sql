UPDATE scan_workflow_steps
SET run_policy = jsonb_set(
        jsonb_set(run_policy, '{depths,standard,params,severity}', '["critical", "high", "medium"]'::jsonb),
        '{depths,deep,params,severity}', '["critical", "high", "medium", "low"]'::jsonb)
WHERE 'vuln.templates' = ANY (capabilities)
  AND run_policy #> '{depths,standard,params,severity}' = '["critical", "high", "medium", "low"]'::jsonb
  AND run_policy #> '{depths,deep,params,severity}' = '["critical", "high", "medium", "low", "info"]'::jsonb;
