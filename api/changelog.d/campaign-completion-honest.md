### Behaviour change: a remediation campaign completes only when its findings are fixed

- A campaign is done when every finding is closed and at least one is verified fixed (`resolved`). Auto-complete no longer fires for a campaign whose findings were all accepted, marked false positive or duplicate.
- Completing a campaign that is not done through `PATCH /api/v1/remediation/campaigns/{id}/status` answers 400 unless the request sets `close_with_open_members: true`; the console asks first and the audit row records `manual_with_open_members`. Responses carry `verified_count`.
- A Jira epic moved to Done completes its campaign only when the campaign is done.
- Restored: a completed campaign can be reopened (`status: active`), and a campaign in validation goes back to active when the validation fails.
- A campaign's due date only moves earlier: a later date or clearing it is refused.
