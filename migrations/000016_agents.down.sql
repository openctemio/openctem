-- =============================================================================
-- Migration 016: Agents (Down)
-- =============================================================================

DROP FUNCTION IF EXISTS recover_stuck_tenant_commands(INTEGER, INTEGER);
DROP FUNCTION IF EXISTS recover_stuck_platform_jobs(INTEGER);
DROP FUNCTION IF EXISTS get_next_platform_job(UUID, TEXT[], TEXT[]);
DROP FUNCTION IF EXISTS fail_exhausted_commands(INTEGER);
DROP FUNCTION IF EXISTS calculate_queue_priority(VARCHAR, TIMESTAMPTZ, UUID);

DROP TRIGGER IF EXISTS trigger_agents_updated_at ON agents;

DROP TABLE IF EXISTS agent_metrics;
DROP TABLE IF EXISTS commands;
DROP TABLE IF EXISTS registration_tokens;
DROP TABLE IF EXISTS agent_api_keys;
DROP TABLE IF EXISTS agents;
