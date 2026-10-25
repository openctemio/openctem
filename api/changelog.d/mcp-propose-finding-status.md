### Added: AI applications connected over MCP can propose a false positive or an accepted risk

- New MCP tool `propose_finding_status` with the write scope `mcp:findings.propose` (permission `findings:write`). Like every write scope it is only granted through an `insufficient_scope` challenge and only when the organization's AI assistants policy lists it (off by default). `oct_` API keys cannot use it.
- The tool files the normal approval request in the name of the person who connected the application, marked with the application's name (`requested_via`, new column on `finding_status_approvals`). The request always waits for another person, whatever the organization's approval level, and the person it was filed for cannot approve it, the solo self-approval included. The finding is read with the person's data scope and the AI egress (TLP) policy first; pentest findings are refused.
- The approval inbox marks such a request "Proposed by AI agent" with the application's name.
