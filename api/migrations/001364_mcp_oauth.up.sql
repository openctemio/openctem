-- OAuth 2.1 for MCP clients (docs/rfcs/RFC-062-mcp-authorization.md).
-- OpenCTEM is the authorization server for its own MCP endpoint: clients,
-- authorization requests (one row per authorization transaction, carrying
-- the code once approved), grants (one user, one organization, one client)
-- and the access and refresh tokens of a grant. Every secret is stored as
-- an HMAC-SHA256 with the application pepper, never in clear.

-- A client an MCP host identifies with: a Client ID Metadata Document (the
-- client_id is its https URL), a client an organization registered, or a
-- dynamically registered one. Public clients only: no secret column.
CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL PRIMARY KEY,
    client_id varchar(2048) NOT NULL,
    kind varchar(32) NOT NULL,
    -- The organization that registered the client (kind organization).
    tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
    name varchar(255) NOT NULL,
    redirect_uris text[] NOT NULL,
    -- When the metadata document was fetched and until when it may be reused.
    metadata_fetched_at timestamptz,
    metadata_expires_at timestamptz,
    blocked_at timestamptz,
    created_at timestamptz DEFAULT now() NOT NULL,
    updated_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT uq_mcp_oauth_clients_client_id UNIQUE (client_id),
    CONSTRAINT chk_mcp_oauth_clients_kind CHECK (kind IN ('metadata_document', 'organization', 'dynamic')),
    CONSTRAINT chk_mcp_oauth_clients_redirects CHECK (cardinality(redirect_uris) BETWEEN 1 AND 20)
);

-- An authorization transaction: created by /oauth/authorize, claimed by the
-- person who opens the consent page, approved (code issued) or denied, then
-- redeemed once at the token endpoint.
CREATE TABLE IF NOT EXISTS mcp_oauth_requests (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL PRIMARY KEY,
    client_ref uuid NOT NULL REFERENCES mcp_oauth_clients(id) ON DELETE CASCADE,
    redirect_uri varchar(2048) NOT NULL,
    state varchar(512) NOT NULL DEFAULT '',
    code_challenge varchar(128) NOT NULL,
    resource varchar(2048) NOT NULL,
    scopes text[] NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'pending',
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
    granted_scopes text[],
    code_hash varchar(128),
    code_expires_at timestamptz,
    -- The grant the code created, revoked if the code is presented again.
    grant_id uuid,
    created_at timestamptz DEFAULT now() NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT chk_mcp_oauth_requests_status CHECK (status IN ('pending', 'approved', 'denied', 'redeemed'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_oauth_requests_code ON mcp_oauth_requests (code_hash) WHERE code_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_requests_expires ON mcp_oauth_requests (expires_at);

-- What a person allowed one client to do in one organization.
CREATE TABLE IF NOT EXISTS mcp_oauth_grants (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_ref uuid NOT NULL REFERENCES mcp_oauth_clients(id) ON DELETE CASCADE,
    resource varchar(2048) NOT NULL,
    scopes text[] NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    last_used_at timestamptz,
    last_used_ip varchar(45),
    -- Absolute end of the grant (refresh tokens never outlive it).
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_reason varchar(64)
);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_grants_user ON mcp_oauth_grants (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_grants_client ON mcp_oauth_grants (client_ref);

ALTER TABLE mcp_oauth_requests DROP CONSTRAINT IF EXISTS fk_mcp_oauth_requests_grant;
ALTER TABLE mcp_oauth_requests
    ADD CONSTRAINT fk_mcp_oauth_requests_grant FOREIGN KEY (grant_id) REFERENCES mcp_oauth_grants(id) ON DELETE SET NULL;

-- Access and refresh tokens of a grant. A rotated refresh token keeps its
-- row with used_at set, so presenting it again is detected as reuse.
CREATE TABLE IF NOT EXISTS mcp_oauth_tokens (
    token_hash varchar(128) NOT NULL PRIMARY KEY,
    grant_id uuid NOT NULL REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE,
    kind varchar(16) NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    CONSTRAINT chk_mcp_oauth_tokens_kind CHECK (kind IN ('access', 'refresh'))
);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_tokens_grant ON mcp_oauth_tokens (grant_id);
CREATE INDEX IF NOT EXISTS idx_mcp_oauth_tokens_expires ON mcp_oauth_tokens (expires_at);
