-- Device authorization grant for MCP clients (RFC 8628, RFC-062 section 6a):
-- a terminal with no browser (an SSH session, a container) shows a short user
-- code; the person enters it in a signed-in browser anywhere and approves on
-- the usual consent page.
--
-- An authorization request now has a flow. A device request has no redirect
-- URI or PKCE challenge (empty strings); it carries the hash of its device
-- code (polled by the client) and of its user code (typed by the person),
-- the polling interval the client must respect, when it last polled, and the
-- address and user agent that asked, which the consent page shows.
-- Constant defaults only: no table rewrite; the tables are small.
ALTER TABLE mcp_oauth_requests ADD COLUMN IF NOT EXISTS flow varchar(16) NOT NULL DEFAULT 'code';
ALTER TABLE mcp_oauth_requests ADD COLUMN IF NOT EXISTS device_code_hash varchar(128);
ALTER TABLE mcp_oauth_requests ADD COLUMN IF NOT EXISTS user_code_hash varchar(128);
ALTER TABLE mcp_oauth_requests ADD COLUMN IF NOT EXISTS poll_interval_seconds integer NOT NULL DEFAULT 5;
ALTER TABLE mcp_oauth_requests ADD COLUMN IF NOT EXISTS last_polled_at timestamptz;
ALTER TABLE mcp_oauth_requests ADD COLUMN IF NOT EXISTS requester_ip varchar(45) NOT NULL DEFAULT '';
ALTER TABLE mcp_oauth_requests ADD COLUMN IF NOT EXISTS requester_ua varchar(256) NOT NULL DEFAULT '';
ALTER TABLE mcp_oauth_requests DROP CONSTRAINT IF EXISTS chk_mcp_oauth_requests_flow;
ALTER TABLE mcp_oauth_requests
    ADD CONSTRAINT chk_mcp_oauth_requests_flow CHECK (
        (flow = 'code' AND device_code_hash IS NULL AND user_code_hash IS NULL)
        OR (flow = 'device' AND device_code_hash IS NOT NULL AND user_code_hash IS NOT NULL));
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_oauth_requests_device_code
    ON mcp_oauth_requests (device_code_hash) WHERE device_code_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_oauth_requests_user_code
    ON mcp_oauth_requests (user_code_hash) WHERE user_code_hash IS NOT NULL;

-- How a grant was obtained, so the organization policy can stop the
-- connections made with a terminal code and the lists can say so.
ALTER TABLE mcp_oauth_grants ADD COLUMN IF NOT EXISTS flow varchar(16) NOT NULL DEFAULT 'code';
ALTER TABLE mcp_oauth_grants DROP CONSTRAINT IF EXISTS chk_mcp_oauth_grants_flow;
ALTER TABLE mcp_oauth_grants ADD CONSTRAINT chk_mcp_oauth_grants_flow CHECK (flow IN ('code', 'device'));

-- The platform's terminal client: the client_id terminals use for the device
-- grant. It has no redirect URI (the device grant uses none), so a client
-- may now list zero redirect URIs; registration still requires at least one
-- for every other client.
ALTER TABLE mcp_oauth_clients DROP CONSTRAINT IF EXISTS chk_mcp_oauth_clients_redirects;
ALTER TABLE mcp_oauth_clients
    ADD CONSTRAINT chk_mcp_oauth_clients_redirects CHECK (cardinality(redirect_uris) BETWEEN 0 AND 20);
INSERT INTO mcp_oauth_clients (client_id, kind, tenant_id, name, redirect_uris)
VALUES ('octc_terminal', 'organization', NULL, 'Terminal sign-in', '{}')
ON CONFLICT (client_id) DO NOTHING;
