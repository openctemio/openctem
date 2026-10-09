### Added: see and disconnect connected AI applications

- My account, Connected applications lists the AI applications (MCP clients)
  you connected in the organization: what they may read, when they were
  connected and last used, and from where. Disconnecting ends access at once.
- Settings, AI access (MCP) gains the organization policy editor and, for
  owners and administrators, every connection in the organization with a
  disconnect. The page now leads with connecting through the browser (no key
  to copy); API keys remain for scripts.
- The platform console lists every AI application with its usage (counts
  only) under System, AI applications, and operators can block one
  everywhere (audited).
- API: `/api/v1/mcp-access/my-connections`, `/api/v1/mcp-access/connections`,
  `/api/v1/admin/mcp-clients` (RFC-062 §12).
