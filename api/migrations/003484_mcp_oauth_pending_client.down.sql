-- Requests that never had a stored client cannot exist under the old schema.
DELETE FROM mcp_oauth_requests WHERE client_ref IS NULL;
ALTER TABLE mcp_oauth_requests DROP CONSTRAINT IF EXISTS chk_mcp_oauth_requests_client;
ALTER TABLE mcp_oauth_requests DROP COLUMN IF EXISTS pending_client;
ALTER TABLE mcp_oauth_requests ALTER COLUMN client_ref SET NOT NULL;
