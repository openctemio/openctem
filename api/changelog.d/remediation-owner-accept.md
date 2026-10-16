### Added: asset owners accept their own remediation suggestions

- A member without `findings:remediation:write` can accept, as it is, a suggestion that adds findings to a task
  assigned to them (or to one of their groups) or creates a task for them, when every finding is in their data
  scope and on an asset they own as primary or secondary owner. Starting a new fix, editing a suggestion,
  leaving findings out and auto-join still need write access. The audit event records `as_owner`.
- `POST /api/v1/remediation/suggestions/{id}/approve` is now gated on `findings:remediation:read`; the service
  enforces the rest (403 otherwise).
