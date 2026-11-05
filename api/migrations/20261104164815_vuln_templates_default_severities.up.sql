-- Default severities of vuln.templates (research 426 decision OD-1,
-- docs/architecture/scan-stages.md §1.5): low to critical at standard
-- depth, info to critical at deep. Info matches are filed as info exposures,
-- not findings (docs/architecture/exposure-taxonomy.md).
--
-- The built-in recon workflows set critical..medium (standard) and
-- critical..low (deep) in their template steps' depth overlays; tenant copies
-- made on use carry the same values. Only steps whose overlays still hold
-- exactly those built-in values change: a severity an organization chose
-- itself is kept. A step without an overlay takes the platform's depth
-- default (code, stage.DepthDefaults).
UPDATE scan_workflow_steps
SET run_policy = jsonb_set(
        jsonb_set(run_policy, '{depths,standard,params,severity}', '["critical", "high", "medium", "low"]'::jsonb),
        '{depths,deep,params,severity}', '["critical", "high", "medium", "low", "info"]'::jsonb)
WHERE 'vuln.templates' = ANY (capabilities)
  AND run_policy #> '{depths,standard,params,severity}' = '["critical", "high", "medium"]'::jsonb
  AND run_policy #> '{depths,deep,params,severity}' = '["critical", "high", "medium", "low"]'::jsonb;
