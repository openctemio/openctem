### Added: filter param of the MCP list tools

- `list_findings` and `search_assets` take `filter`, the console search box syntax (`severity>=high kev=true -status:accepted`, `type=subdomain domain=example.com last_seen<7d`), ANDed with the other params. It is parsed and planned by the query language as the key's owner, with the same field permissions, and runs through the list's own registry, so tenant, data scope and limits are those of the console. Problems are reported by code and position, never by value.
- `search_assets` now runs on the inventory registry (the same filter as `GET /assets`): its total is capped at 10,000 (`total_capped`).
