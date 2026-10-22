### Added: bug-bounty report fields on findings

- `POST /api/v1/findings` accepts a `bounty_report` object for `bug_bounty` findings, and `PUT /api/v1/findings/{id}/bounty-report` replaces it (`findings:write`). Finding reads return it as `bounty_report` (RFC-121).
- Setting or changing a report's reward or disclosure also needs `findings:triage` (403 `TRIAGE_PERMISSION_REQUIRED`); every change writes the audit action `finding.bounty_report_changed` with the old and new value of each changed field.
- A second finding for the same intake and report id is refused with 409.

### Security: bug-bounty findings are never AI-triaged automatically

- Reporter text is untrusted: findings with source `bug_bounty` are no longer queued for automatic AI triage when they are created; a person can still ask for it.
- The rule holds on every AI triage entry path: auto-triage, workflow `trigger_ai_triage` actions and requests without a user are refused (403 `AI_POLICY_RESTRICTED`, bulk item `ai_policy_restricted`), the worker fails such a queued row before the model call, and a person's requested verdict on a `bug_bounty` finding creates no false-positive proposal and dispatches no workflow event.
