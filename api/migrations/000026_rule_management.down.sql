-- =============================================================================
-- Migration 026: Rule Management (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_rule_overrides_updated_at ON rule_overrides;
DROP TRIGGER IF EXISTS trigger_rules_updated_at ON rules;
DROP TRIGGER IF EXISTS trigger_rule_sources_updated_at ON rule_sources;

DROP TABLE IF EXISTS rule_sync_history;
DROP TABLE IF EXISTS rule_bundles;
DROP TABLE IF EXISTS rule_overrides;
DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS rule_sources;

