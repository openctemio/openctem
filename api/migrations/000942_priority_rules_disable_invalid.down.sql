-- Switch the rules back on that 000942 switched off (only those still off and
-- unchanged since), then drop the report.
UPDATE priority_override_rules r
   SET is_active = TRUE, updated_at = NOW()
  FROM priority_rule_safety_report rep
 WHERE rep.rule_id = r.id
   AND r.is_active = FALSE
   AND r.conditions IS NOT DISTINCT FROM rep.conditions;

DROP TABLE IF EXISTS priority_rule_safety_report;
