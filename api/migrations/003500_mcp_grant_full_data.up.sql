-- A person whose role has full organization data access may allow one MCP
-- connection to read all organization data (RFC-062, MA25). The choice is
-- stored on the authorization request (carried to the grant at code
-- redemption) and on the grant. Off for every existing row: a connection
-- keeps reading only what its user's scope rows allow unless its owner
-- turned this on at consent. Constant default, so no table rewrite.
ALTER TABLE mcp_oauth_requests ADD COLUMN IF NOT EXISTS full_data boolean NOT NULL DEFAULT false;
ALTER TABLE mcp_oauth_grants ADD COLUMN IF NOT EXISTS full_data boolean NOT NULL DEFAULT false;
