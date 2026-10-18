# Security overview and audit log export

Two read features for organization owners and administrators: a security
overview (what to fix first) and a download of the audit log.

Status: shipped. Key files: `internal/app/securityoverview/service.go`,
`internal/infra/postgres/security_overview_repository.go`,
`internal/infra/http/handler/security_overview_handler.go`,
`internal/app/audit/export.go`, `internal/infra/http/handler/audit_export_handler.go`.

## Security overview

`GET /api/v1/organization/security-overview` on the token-tenant chain, gated by
`RequireAdmin` and `settings:read`. The organization comes from the credential
only. It is computed on every request (a few tenant-scoped counts, no cache) and
sent with `Cache-Control: no-store`.

The server returns no human text. Each check has an `id`, a `group`, a `status`
(`pass`, `warn`, `risk`, `info`), an optional `count` and a console `link`; the
web console renders the title and explanation from its dictionaries by check id
(`securityOverview.check.<id>.title` and `.desc`), so every language shows the
same overview.

| Check id | Rule | Link |
| --- | --- | --- |
| `sign_in.mfa_admins_required` | two-factor required for everyone or for owners and administrators: pass, else risk | `/settings/authentication` |
| `sign_in.admins_without_mfa` | active owners and administrators with a local account and no second factor (single sign-on accounts are covered by their identity provider): none pass, else risk | `/settings/members` |
| `sign_in.email_verification` | mode `never`: warn, else pass | `/settings/authentication` |
| `sign_in.ip_allowlist` | configured: pass, empty: info | `/settings/authentication` |
| `people.dormant_members` | active people (not service accounts) who last signed in over 90 days ago, or never signed in and joined over 30 days ago: warn | `/settings/members` |
| `people.join_requests` | pending, unexpired join requests: warn | `/settings/members` |
| `credentials.api_keys_expiring` | active keys expiring within 14 days: warn | `/settings/api-keys` |
| `credentials.api_keys_unused` | active, unexpired keys never used and created over 30 days ago, or last used over 90 days ago: warn | `/settings/api-keys` |
| `credentials.scim_tokens_unused` | active tokens unused (same windows): warn; no active token: info | `/settings/scim` |
| `scanning.sensor_opt_ins` | out-of-band callbacks or custom templates allowed for sensors: warn | `/settings/authentication` |
| `scanning.private_target_policy` | sensors without a local policy may take private targets: info | `/settings/authentication` |
| `organization.verified_domain` | at least one verified SSO domain: pass, else info | `/settings/domains` |
| `organization.support_access` | an active support grant: warn | `/settings/support-access` |

A source that is not wired (settings or counts) omits its checks instead of
failing the response.

### Score

`score = round(100 * (1 - penalty / maxPenalty))`. A failing check weighs 3 when
it is a risk-class check (`sign_in.mfa_admins_required`,
`sign_in.admins_without_mfa`) and 1 otherwise; a failed check adds its weight to
`penalty`, and every scored check (passing or failing) adds its weight to
`maxPenalty`. `info` checks are in neither. No scored check gives 100.

### Tenant isolation

Every count is one query with `WHERE tenant_id = $1` on each table; the
Postgres test `TestSecurityOverviewCounts_WindowsAndTenantIsolation` proves
another tenant's rows never count and pins the 89 and 91 day edges.

## Audit log export

`GET /api/v1/audit-logs/export?format=csv|jsonl` has the gate of the list
(`audit:read`, plus the list's full-data-access rule) and the filters of the
list (`actor_id`, `action`, `resource_type`, `resource_id`, `result`, `severity`,
`request_id`, `since`, `until`, `search`, `exclude_system`), parsed by the same
function. Paging and sort are ignored: rows stream newest first, in keyset pages
of 500, without loading the result in memory.

- Cap: 50,000 rows (`MaxExportRows`). Before the first byte the handler probes
  whether more rows match; if so it sets `X-Export-Truncated: true`. JSON lines
  end with `{"truncated":true}` in that case.
- Columns: `time` (RFC 3339 UTC), `action`, `severity`, `result`, `actor_id`,
  `actor_email`, `resource_type`, `resource_id`, `resource_name`, `ip`,
  `request_id`, `changes`. In CSV `changes` is a JSON string; in JSON lines it is
  a JSON value.
- CSV cells that start with `=`, `+`, `-`, `@`, tab or carriage return get a
  leading apostrophe (the one rule all CSV exports use).
- File name: `audit-log-<organization>-<UTC time>.<csv|jsonl>`, as an attachment.
- Limits: one export at a time per person, and the tenant's heavy-read cap.
- Audit: every export writes an `audit_log.exported` event (medium severity)
  after the stream, with the format, the names of the filters used (never their
  values), the row count and whether it was truncated or ended early.
- Isolation: the repository refuses a filter without a tenant; system rows
  (no tenant) are never exported.
