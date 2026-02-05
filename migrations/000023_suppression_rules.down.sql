-- =============================================================================
-- Migration 023: Suppression Rules (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_suppression_rules_updated_at ON suppression_rules;
DROP FUNCTION IF EXISTS expire_suppression_rules();

DROP TABLE IF EXISTS suppression_rule_audit;
DROP TABLE IF EXISTS finding_suppressions;
DROP TABLE IF EXISTS suppression_rules;

