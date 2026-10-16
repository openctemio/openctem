### Added: approval policy evaluator

- `pkg/domain/approvalpolicy` decides, for a false positive, an accepted risk, a suppression rule or a remediation task exception, the tier (single, peer, security, dual), who may approve (security pool with a recorded fallback; the requester and the asset's owners excluded, the assignee optionally), how many approvers, the acceptance cap and decision deadline, and what a later material change does (RFC-111).
- Platform floors cannot be lowered by an organization's policy: four-eyes on an accepted risk is always on; a relaxing policy change is detected for the 24-hour delay.
- Not wired into any request path yet; no behavior changes.
