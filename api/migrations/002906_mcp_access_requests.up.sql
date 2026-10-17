-- Requests from members to approve an AI application publisher
-- (docs/architecture/mcp-authorization.md, "Access requests").
-- A member whose consent is blocked because the organization only admits
-- verified applications asks an administrator to approve the application's
-- publisher host. The server derives every field from the stored
-- authorization request; the member supplies nothing. One pending row per
-- organization and host: repeated requests bump request_count.
CREATE TABLE IF NOT EXISTS mcp_access_requests (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_host varchar(253) NOT NULL,
    client_name varchar(200) NOT NULL,
    client_id text NOT NULL,
    scopes text[] NOT NULL DEFAULT '{}',
    requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
    request_count integer NOT NULL DEFAULT 1,
    status varchar(16) NOT NULL DEFAULT 'pending',
    decided_by uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at timestamptz,
    created_at timestamptz DEFAULT now() NOT NULL,
    updated_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT chk_mcp_access_requests_status CHECK (status IN ('pending', 'approved', 'denied')),
    CONSTRAINT chk_mcp_access_requests_client_id CHECK (length(client_id) <= 2048)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_mcp_access_requests_pending
    ON mcp_access_requests (tenant_id, client_host) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_mcp_access_requests_tenant_requester
    ON mcp_access_requests (tenant_id, requested_by, created_at);
