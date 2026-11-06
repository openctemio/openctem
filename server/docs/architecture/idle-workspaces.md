# Idle-organization policy

An organization the idle policy is **on** for, that nobody signs in to,
moves through a lifecycle, so abandoned workspaces do not accumulate on a
shared platform.

**The policy is off for every organization by default.** It applies only
where a platform administrator turned it on for that organization (or, on a
hosted service, the service operator did through the same switch). A
self-hosted install never makes an organization read-only on its own, with
or without self-service sign-up. Migration `idle_policy_opt_in` turned the
policy off for every existing organization and returned them to `active`.

## Stages

"Idle" is the time since the latest sign-in of any active member (or since
the organization was created, if nobody ever signed in).

| Idle | Stage | What happens |
|------|-------|--------------|
| < 60 days | `active` | nothing |
| 60 days | `reminded` | the owners and admins are emailed: sign in to keep it |
| 90 days | `read_only` | first warning; changes are refused (403 `WORKSPACE_READ_ONLY`), reads and exports keep working |
| 113 days | `final_warning` | last warning: the deletion date |
| 120 days | `deletion_due` | the platform administrators are alerted (email + WARN `alert=idle_workspace_deletion_due`); **nothing is deleted automatically** |

- One step per sweep, never skipping a warning, and at least 7 days between
  two warnings: an organization found idle for 200 days on its first sweep is
  reminded first.
- **A sign-in by any member undoes it at once.** Read-only lifts on the next
  request after the sign-in (the check compares sign-ins with when the stage
  started); the next sweep returns the stage to `active` and audits it.
- Every stage change is written to the organization's audit log
  (`tenant.idle_reminded`, `tenant.idle_read_only`, `tenant.idle_final_warning`,
  `tenant.idle_deletion_due`, `tenant.idle_reactivated`; actor
  `system:idle-workspaces`).
- Deletion stays a platform administrator's decision in the console, after
  the owners had the chance to export. Automatic deletion (with an export
  link in the final email) is a follow-up once organization export exists.

## Turning the policy on or off

A platform administrator turns the policy on or off per organization. A
reason (1-500 characters) is required both ways. Either way the
organization returns to `active`: turning it on starts counting from the
latest sign-in, turning it off lifts read-only at once.

| Endpoint | Who |
|----------|-----|
| `GET /api/v1/admin/tenants/{tenantId}/idle` | any admin (policy on or off, stage, last sign-in, read-only now) |
| `PUT /api/v1/admin/tenants/{tenantId}/idle/policy` `{enabled, reason}` | **ops_admin+**; audited high in the admin log (`organization.idle_policy_changed`) and in the organization's log (`tenant.idle_policy_changed`) |

## Read-only enforcement

`middleware.IdleReadOnly` runs in the shared tenant chain
(`buildBaseMiddlewares`): any method but GET, HEAD and OPTIONS on an
organization in `read_only`, `final_warning` or `deletion_due` (policy on,
no sign-in since the stage started) is refused with 403
`WORKSPACE_READ_ONLY`. The answer is cached for a minute per organization.
A read error lets the request through: read-only is a nudge, not a security
boundary, and must never take an organization down.

## Code map

- `pkg/domain/lifecycle`: stages, thresholds, `Decide`.
- `internal/app/lifecycle`: the sweep, the read-only check, the policy switch.
- `internal/infra/postgres/idle_lifecycle_repository.go`: migrations 001347
  (`tenant_idle_lifecycle`) and `idle_policy_opt_in` (`policy_enabled`),
  every query scoped by `tenant_id`.
- `internal/infra/controller/idle_workspaces.go`: the sweep every 6 hours.
- `cmd/server/idle_workspace_mailer.go`: the emails.
