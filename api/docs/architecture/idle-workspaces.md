# Idle Free workspaces

An organization on the **Free** plan that nobody signs in to moves through a
lifecycle, so abandoned workspaces do not accumulate on a shared platform.
Paid plans (Pro, Enterprise) and organizations without a plan are never
touched. Owner decision 2026-10-08 (research/71 §7.1).

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

## Exemption

A platform administrator can exempt an organization (a design partner, a
pilot): it returns to `active` and is never swept until the exemption is
lifted. A reason is required (1-500 characters).

| Endpoint | Who |
|----------|-----|
| `GET /api/v1/admin/tenants/{tenantId}/idle` | any admin (stage, last sign-in, read-only now, exemption) |
| `PUT /api/v1/admin/tenants/{tenantId}/idle/exemption` `{exempt, reason}` | **ops_admin+**; audited high in the admin log and in the organization's log |

## Read-only enforcement

`middleware.IdleReadOnly` runs in the shared tenant chain
(`buildBaseMiddlewares`): any method but GET, HEAD and OPTIONS on an
organization in `read_only`, `final_warning` or `deletion_due` (not exempt,
no sign-in since the stage started) is refused with 403
`WORKSPACE_READ_ONLY`. The answer is cached for a minute per organization.
A read error lets the request through: read-only is a nudge, not a security
boundary, and must never take an organization down.

## Code map

- `pkg/domain/lifecycle`: stages, thresholds, `Decide`.
- `internal/app/lifecycle`: the sweep, the read-only check, the exemption.
- `internal/infra/postgres/idle_lifecycle_repository.go`: migration 001347
  (`tenant_idle_lifecycle`), every query scoped by `tenant_id`.
- `internal/infra/controller/idle_workspaces.go`: the sweep every 6 hours.
- `cmd/server/idle_workspace_mailer.go`: the emails.
