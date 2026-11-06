-- Standard depth port scan runs the top 1000 ports, as coverage and the
-- platform's default port set do (docs/architecture/scan-stages.md).
--
-- Only the two system recon templates change (Standard recon and Deep recon,
-- whose port step set top_n 100 at Standard depth). A tenant's copy of a
-- template has its own workflow and step ids, is not a system template and is
-- never touched: an edited copy keeps its value, and the template-update
-- check offers the new value to a copy that still matches its source.
-- Idempotent: only a step whose Standard top_n is still 100 changes.

UPDATE scan_workflow_steps st
SET run_policy = jsonb_set(st.run_policy, '{depths,standard,params,top_n}', '1000'::jsonb)
FROM scan_workflows w
WHERE w.id = st.scan_workflow_id
  AND w.is_system_template
  AND st.scan_workflow_id IN ('a0000002-0000-0000-0000-000000000013', 'a0000002-0000-0000-0000-000000000015')
  AND st.step_key = 'ports'
  AND st.run_policy #> '{depths,standard,params,top_n}' = '100'::jsonb;
