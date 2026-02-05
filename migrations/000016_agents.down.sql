-- =============================================================================
-- Migration 016: Agents (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_agents_updated_at ON agents;

DROP TABLE IF EXISTS agent_metrics;
DROP TABLE IF EXISTS commands;
DROP TABLE IF EXISTS registration_tokens;
DROP TABLE IF EXISTS agent_api_keys;
DROP TABLE IF EXISTS agents;
