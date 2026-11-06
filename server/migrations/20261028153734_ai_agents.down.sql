-- Removes AI agents. The service accounts behind them stay (they are plain
-- service accounts again); delete them from Settings if they are not wanted.
DROP TRIGGER IF EXISTS trigger_refuse_ai_agent_with_credentials ON ai_agents;
DROP FUNCTION IF EXISTS refuse_ai_agent_with_credentials();
DROP TRIGGER IF EXISTS trigger_refuse_ai_agent_api_key ON api_keys;
DROP TRIGGER IF EXISTS trigger_refuse_ai_agent_mcp_grant ON mcp_oauth_grants;
DROP TRIGGER IF EXISTS trigger_refuse_ai_agent_role ON user_roles;
DROP FUNCTION IF EXISTS refuse_ai_agent_credential();
DROP TRIGGER IF EXISTS trigger_label_ai_agent_activity ON finding_activities;
DROP FUNCTION IF EXISTS label_ai_agent_activity();
DROP TABLE IF EXISTS ai_runs;
DROP TABLE IF EXISTS ai_agent_owners;
DROP FUNCTION IF EXISTS refuse_foreign_ai_agent_owner();
DROP TABLE IF EXISTS ai_agents;
DROP FUNCTION IF EXISTS refuse_ai_agent_non_service();
