-- A Client ID Metadata Document client is stored only once a signed-in person
-- approves it (RFC-062 section 5). Until then the authorization request carries
-- the fetched document itself: client_ref stays empty and pending_client holds
-- the client_id, name, redirect URIs and fetch times.
ALTER TABLE mcp_oauth_requests ALTER COLUMN client_ref DROP NOT NULL;
ALTER TABLE mcp_oauth_requests ADD COLUMN IF NOT EXISTS pending_client jsonb;
ALTER TABLE mcp_oauth_requests DROP CONSTRAINT IF EXISTS chk_mcp_oauth_requests_client;
ALTER TABLE mcp_oauth_requests
    ADD CONSTRAINT chk_mcp_oauth_requests_client CHECK (client_ref IS NOT NULL OR pending_client IS NOT NULL);

-- Clean-up of registry pollution: metadata-document clients that nobody ever
-- approved (no grant), with no authorization request in the last day, and not
-- blocked. Their requests go with them (ON DELETE CASCADE).
DELETE FROM mcp_oauth_clients c
 WHERE c.kind = 'metadata_document'
   AND c.blocked_at IS NULL
   AND NOT EXISTS (SELECT 1 FROM mcp_oauth_grants g WHERE g.client_ref = c.id)
   AND NOT EXISTS (SELECT 1 FROM mcp_oauth_requests r WHERE r.client_ref = c.id AND r.created_at > now() - interval '1 day');
