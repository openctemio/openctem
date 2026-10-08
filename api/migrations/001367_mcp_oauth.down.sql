DROP TABLE IF EXISTS mcp_oauth_tokens;
ALTER TABLE IF EXISTS mcp_oauth_requests DROP CONSTRAINT IF EXISTS fk_mcp_oauth_requests_grant;
DROP TABLE IF EXISTS mcp_oauth_grants;
DROP TABLE IF EXISTS mcp_oauth_requests;
DROP TABLE IF EXISTS mcp_oauth_clients;
