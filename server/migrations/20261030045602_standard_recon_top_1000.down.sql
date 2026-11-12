-- Back to top 100 at Standard depth on the two system recon templates.
UPDATE scan_workflow_steps st
SET run_policy = jsonb_set(st.run_policy, '{depths,standard,params,top_n}', '100'::jsonb)
FROM scan_workflows w
WHERE w.id = st.scan_workflow_id
  AND w.is_system_template
  AND st.scan_workflow_id IN ('a0000002-0000-0000-0000-000000000013', 'a0000002-0000-0000-0000-000000000015')
  AND st.step_key = 'ports'
  AND st.run_policy #> '{depths,standard,params,top_n}' = '1000'::jsonb;
