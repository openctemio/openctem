### Added: members can ask administrators to approve an AI application

- A member whose AI application is blocked because the organization only admits approved applications can now press "Request access" on the consent page. Administrators get an in-app notification and approve or decline the request in Settings, AI assistants (MCP), Applications; approving adds the application's publisher host to the organization's approved publishers. An owner or administrator can also approve the publisher directly from the consent page and continue connecting.
- The server takes every detail of a request from the stored authorization request; requests are limited to 5 new ones per member per day and 50 waiting per organization. Approving needs `settings:write` and a recent sign-in; requests, approvals and declines are audited (`mcp_access_request.created`, `.approved`, `.denied`).
- New endpoints: `POST /api/v1/oauth/requests/{id}/access-request`, `POST /api/v1/oauth/requests/{id}/allow-publisher`, `GET /api/v1/mcp-access/requests`, `POST /api/v1/mcp-access/requests/{id}/approve`, `POST /api/v1/mcp-access/requests/{id}/deny`. Migration `002902_mcp_access_requests` adds one table.

### Fixed: the comment-adding AI scope can be allowed in the organization policy

- The policy refused `mcp:findings.comment` as an unknown scope shape, so no organization could let AI applications add (person-confirmed) comments to findings. It is accepted now.
