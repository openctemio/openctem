-- Removes the device grant: the terminal client and everything it was
-- granted (cascade), device requests, and the columns.
DELETE FROM mcp_oauth_clients WHERE client_id = 'octc_terminal';
DELETE FROM mcp_oauth_requests WHERE flow = 'device';
DELETE FROM mcp_oauth_grants WHERE flow = 'device';
ALTER TABLE mcp_oauth_clients DROP CONSTRAINT IF EXISTS chk_mcp_oauth_clients_redirects;
ALTER TABLE mcp_oauth_clients
    ADD CONSTRAINT chk_mcp_oauth_clients_redirects CHECK (cardinality(redirect_uris) BETWEEN 1 AND 20);
ALTER TABLE mcp_oauth_grants DROP CONSTRAINT IF EXISTS chk_mcp_oauth_grants_flow;
ALTER TABLE mcp_oauth_grants DROP COLUMN IF EXISTS flow;
DROP INDEX IF EXISTS uq_mcp_oauth_requests_user_code;
DROP INDEX IF EXISTS uq_mcp_oauth_requests_device_code;
ALTER TABLE mcp_oauth_requests DROP CONSTRAINT IF EXISTS chk_mcp_oauth_requests_flow;
ALTER TABLE mcp_oauth_requests DROP COLUMN IF EXISTS requester_user_agent;
ALTER TABLE mcp_oauth_requests DROP COLUMN IF EXISTS requester_ip;
ALTER TABLE mcp_oauth_requests DROP COLUMN IF EXISTS last_polled_at;
ALTER TABLE mcp_oauth_requests DROP COLUMN IF EXISTS poll_interval_seconds;
ALTER TABLE mcp_oauth_requests DROP COLUMN IF EXISTS user_code_hash;
ALTER TABLE mcp_oauth_requests DROP COLUMN IF EXISTS device_code_hash;
ALTER TABLE mcp_oauth_requests DROP COLUMN IF EXISTS flow;
