-- Out-of-band confirmation of MCP write tools (docs/rfcs/RFC-062-mcp-authorization.md §10).
-- A write tool called by an AI application does nothing until the person the
-- connection belongs to approves the exact action in the OpenCTEM web UI;
-- the confirmation is bound to the connection, the tool and a digest of the
-- arguments, lives five minutes and is used once.
CREATE TABLE IF NOT EXISTS mcp_action_confirmations (
    id uuid DEFAULT public.uuid_generate_v7() NOT NULL PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    grant_id uuid NOT NULL REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tool varchar(64) NOT NULL,
    args_digest varchar(64) NOT NULL,
    -- What the person is shown, built by the server (never by the client).
    summary text NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'pending',
    created_at timestamptz DEFAULT now() NOT NULL,
    expires_at timestamptz NOT NULL,
    decided_at timestamptz,
    CONSTRAINT chk_mcp_action_confirmations_status CHECK (status IN ('pending', 'approved', 'denied', 'used')),
    CONSTRAINT chk_mcp_action_confirmations_summary CHECK (length(summary) <= 12000)
);
CREATE INDEX IF NOT EXISTS idx_mcp_action_confirmations_expires ON mcp_action_confirmations (expires_at);
CREATE INDEX IF NOT EXISTS idx_mcp_action_confirmations_grant ON mcp_action_confirmations (grant_id);
