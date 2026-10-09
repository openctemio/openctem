### Added: AI applications can add finding comments, each confirmed by you

- First MCP write tool, `add_finding_comment` (scope `mcp:findings.write`,
  permission `findings:write`): an internal comment, never sent to
  integrations (RFC-062).
- Nothing changes until the person who connected the application confirms
  the exact comment in OpenCTEM at `/mcp/confirm/<id>`; the confirmation is
  bound to the connection, the tool and the arguments, lasts five minutes
  and is used once. API keys cannot run write tools.
- Write scopes are off by default: an organization enables them by listing
  `mcp:findings.write` in its MCP policy. Applications ask for the scope
  only when they need it (`insufficient_scope` step-up).
- Audited: `mcp_action.requested`, `mcp_action.confirmed`,
  `mcp_action.refused`. Migration `001522_mcp_action_confirmations`.
