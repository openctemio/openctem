-- Rollback Phase A — drop the catalog FK and table.
--
-- Pure additive migration up; rollback removes only what we added,
-- existing finding rows unchanged. The (tool_name, rule_id) data
-- on findings remains the source of truth in the rolled-back state.

BEGIN;

DROP INDEX IF EXISTS idx_findings_detection_rule_id;
ALTER TABLE findings DROP COLUMN IF EXISTS detection_rule_id;

DROP INDEX IF EXISTS idx_detection_rules_status;
DROP INDEX IF EXISTS idx_detection_rules_cve_ids_gin;
DROP INDEX IF EXISTS idx_detection_rules_scanner_category;
DROP TABLE IF EXISTS detection_rules;

COMMIT;

-- Note: BEGIN/COMMIT in down.sql wraps the statements above. Trigger
-- drop happens implicitly when we drop the column — but if down is
-- ever run in a state where the column survives (partial rollback),
-- the trigger needs explicit drop. Idempotent: skipped if absent.
DROP TRIGGER IF EXISTS trg_findings_populate_detection_rule_id ON findings;
DROP FUNCTION IF EXISTS findings_populate_detection_rule_id();
