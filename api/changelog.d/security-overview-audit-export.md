### Added: security overview and audit log export

- `GET /api/v1/organization/security-overview` (owners and administrators with `settings:read`) returns a score and 13 posture checks: sign-in, people, credentials, scanning and organization. The console shows them in Settings > Security overview.
- `GET /api/v1/audit-logs/export?format=csv|jsonl` (`audit:read`) downloads the audit log with the list's filters, newest first, up to 50,000 rows (`X-Export-Truncated: true` when more match). CSV cells that start with a formula character are neutralised. Each export is itself recorded as an `audit_log.exported` event. The audit log page has an Export button.
- No migration and no upgrade step.
