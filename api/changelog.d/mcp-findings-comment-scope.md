### Changed: the MCP comment tool needs only findings:comment

- `add_finding_comment` now requires `findings:comment` (split from
  `findings:write`), and its OAuth scope is renamed `mcp:findings.write` →
  `mcp:findings.comment`. An AI application allowed to comment can no longer
  stand on `findings:write` or `findings:severity`.
- Migration `001556_mcp_findings_comment_scope` renames the scope in existing
  connections, pending requests and organization MCP policies, so nothing
  needs reconnecting.
