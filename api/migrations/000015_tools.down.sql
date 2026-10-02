-- =============================================================================
-- Migration 015: Tools and Tool Categories (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_tenant_tool_configs_updated_at ON tenant_tool_configs;
DROP TRIGGER IF EXISTS trigger_tools_updated_at ON tools;
DROP TRIGGER IF EXISTS trigger_tool_categories_updated_at ON tool_categories;

-- NOTE: tool_executions is dropped in 000033_tool_executions.down.sql
DROP TABLE IF EXISTS tenant_tool_configs;
DROP TABLE IF EXISTS tools;
DROP TABLE IF EXISTS tool_categories;
