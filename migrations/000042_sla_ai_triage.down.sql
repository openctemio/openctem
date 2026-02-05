-- =============================================================================
-- Migration 042: SLA Policies & AI Triage Results (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_ai_triage_updated_at ON ai_triage_results;
DROP TRIGGER IF EXISTS trigger_sla_policies_updated_at ON sla_policies;
DROP TABLE IF EXISTS ai_triage_results;
DROP TABLE IF EXISTS sla_policies;
