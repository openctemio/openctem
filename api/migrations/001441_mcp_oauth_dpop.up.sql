-- DPoP (RFC 9449) for MCP grants (docs/rfcs/RFC-062-mcp-authorization.md §9):
-- the SHA-256 thumbprint of the client key a grant is bound to. A bound
-- grant only accepts requests carrying a proof signed by that key.
ALTER TABLE mcp_oauth_grants ADD COLUMN IF NOT EXISTS dpop_jkt varchar(64);
