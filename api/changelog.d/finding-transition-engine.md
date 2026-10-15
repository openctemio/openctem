### Added: one transition engine for finding status changes, and the allowed moves of a finding

- Every status change made by a person or a delegated actor is decided by one engine. That covers the status endpoint, bulk status, the fix-applied / verify / reject-fix actions and their by-filter variants, approval requests and decisions, remediation group and campaign resolves, workflow `update_status`, and the Jira and GitHub webhooks. Approvals still need a second person, as before.
- `GET /api/v1/findings/{id}/transitions` lists every move from the finding's status for the caller: allowed or not, how (direct, an approval request, the duplicate picker), the inputs it needs, and reason codes when blocked.
- `POST /api/v1/findings/transitions:evaluate` (`finding_ids`, at most 100, and `to`) is a dry run with a decision per finding.
- Both need `findings:read`, and both are tenant- and data-scoped: out-of-scope findings are 404 on the GET and `not_found` in the dry run.
- The MCP tool `list_finding_transitions` returns the same answer.
- A false-positive or accepted-risk request is refused (404) for a finding outside the caller's data scope.
- Pentest findings are refused on the verify and reject-fix actions too, as on every other status route. The pentest module owns their moves.
