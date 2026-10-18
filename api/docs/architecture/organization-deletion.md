# Organization deletion with a grace period

An owner's request to delete an organization is not carried out at once. The
organization is closed to everyone immediately and deleted when the grace
period (14 days, `tenant.DeletionGrace`) ends; until then any owner can cancel
and everything works again as before. A platform administrator can delete an
organization at once from the console.

| | Owner request | Console "Delete now" |
|---|---|---|
| Route | `DELETE /api/v1/tenants/{tenant}` (owner, `team:delete`, recent sign-in) answers 202 with `deletion_due_at` | `POST /api/v1/admin/tenants/{tenantId}/purge` (super_admin, fresh authenticator code, reason) |
| Effect | `tenants.status = 'pending_deletion'`, `deletion_due_at = now + 14 days`; refused to every credential at once (the organization access gate, see `organization-suspension.md`); live connections close | deleted at once, whatever its status |
| Audit | critical entry in the organization's log (`tenant.deletion_scheduled`); the deletion itself on the platform chain (`tenant.deleted`) | critical admin audit row `organization.purged` with the reason, plus `tenant.deleted` |
| Undo | `POST /api/v1/auth/organization-deletion/cancel` by any active owner until the due time (`tenant.deletion_canceled`) | none |

The purge worker (`organization-delete`, every `WORKER_INVITATION_PURGE_INTERVAL`)
deletes the organizations whose grace ended through the same
`TenantService.DeleteTenant` the immediate deletion uses: stored files first,
then the rows (cascade), then a record on the platform audit chain. A failure
(storage down) leaves the organization pending and is retried on the next
run; one failure does not stop the others. Member accounts are kept.

## Cancelling

A pending organization is refused to tenant tokens, so an owner cancels from
the sign-in page: the sign-in response lists the organization among the
suspended memberships with `organization_suspended: true` and
`deletion_due_at`, the web app offers "Cancel deletion" to owners, and the
cancel call authenticates with the session's refresh token (in the body, or
the cookie with the CSRF pair), like the first-team and onboarding steps.
The service re-checks that the caller is an active owner (effective role
`owner`, active membership, active account) in the database; anyone else
gets the same 403 whether or not the organization exists.

## Threat model

- **A stolen owner session deletes the organization.** The request needs a
  recent sign-in (step-up), and the 14-day grace leaves the real owners time
  to notice (every member is refused from that moment) and cancel.
- **Data written during the grace.** None: the organization is refused to
  every credential (sessions, API keys, MCP, sensors, SCIM, CI, webhooks) and
  its scheduled work is skipped, exactly as for a suspension.
- **Cancel by a non-owner, or probing.** The cancel checks ownership before
  anything else and answers the same 403 for a missing organization; it is
  rate limited like token exchange.
- **The console deletes the wrong organization.** super_admin only, a fresh
  authenticator code (not the step-up window), a reason, a critical audit
  row; the platform's system organization is refused.
- **A purge that fails half way.** Stored files are erased before the rows
  and the deletion is refused when they cannot be; the status cache is
  forgotten so the organization's real status applies again.

## Data

Migration `organization_deletion_grace`: `tenants.status` gains
`pending_deletion`; `deletion_requested_at`, `deletion_requested_by` (users,
`ON DELETE SET NULL`) and `deletion_due_at`; a check keeps the due date and
the status together; a partial index serves the worker. The down migration
returns pending organizations to `active`.

## Tests

- `internal/app/orgdeletion/service_test.go`: owner-only schedule and cancel,
  conflicts, system organization, cache and sockets, purge continues past a
  failure, console purge (reason, failure audited and cache forgotten).
- `internal/app/orgdeletion/service_db_test.go`: against a migrated database,
  schedule refused at the gate at once, nothing deleted before the grace,
  cancel reopens, the worker deletes after the grace through the real tenant
  delete, member accounts kept.
- Web: the delete dialog's scheduled message, the sign-in cancel dialog, the
  console badge, notice and "Delete now".
