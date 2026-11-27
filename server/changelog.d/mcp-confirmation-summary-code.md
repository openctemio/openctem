### Added: pending MCP write confirmations carry a message code and typed values

- A pending write-action confirmation now also stores a stable message code and typed values beside the English summary, so the web can show it in the reader's language and show the AI-written comment text and the client visibility as separate fields (a comment that imitates a "Visible to the campaign's client" line can no longer pass for the real one). For `add_finding_comment`: code `mcp.add_finding_comment`, values `finding`, `severity`, `content` and, on a pentest finding only, `client_visible`.
- `GET /api/v1/mcp-access/confirmations/{id}` adds `summary_code` and `summary_params` (omitted when empty, for confirmations created earlier). The English `summary` is unchanged.
- An invalid code or oversized values are not stored; the request still succeeds with the English summary.
- Migration `mcp_confirmation_summary_code` (two nullable columns, checks added not valid then validated; no backfill).
- Docs: server/docs/architecture/mcp-authorization.md
