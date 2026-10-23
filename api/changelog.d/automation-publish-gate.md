### Security: going live with an automation is gated by what it can do

- The new permissions are `automations:read`, `automations:write` and `automations:publish`. Write covers drafts, preview, validate and manual runs. Publish covers going live, approving another person's version, rolling back, changing the mode, switching an automation on or off, and deleting it.
- Publishing a low-risk automation (tags only) needs `automations:publish`. An elevated one (status, assignment, tickets, notifications, AI triage) also needs a recent re-authentication. A high-risk one (scans, request actions, automation chaining, a raised change cap) waits until a second person with `automations:publish` approves the exact version they reviewed (`POST /api/v1/workflows/{id}/versions/{versionId}/approve`). The publisher cannot approve their own version, and a newer publish request voids an older pending one. A draft with blocking validate problems cannot be published.
- The catalog entries and versions carry `risk_class`. Versions show the publisher's and approver's names.

### Behaviour change: automation permissions renamed

- Migration 003352 (`automations_permissions`) renames `findings:workflows:read` and `findings:workflows:write` to `automations:read` and `automations:write` in roles, role-template snapshots and API key scopes, with no aliases. It grants `automations:publish` to every role and API key that held write. The security-analyst and vulnerability-manager role templates move to version 3, whose only change is the rename.
- **Upgrade note:** stop the old API before migrating, because it checks the old ids. API clients that request scopes by id must use the new ids.
