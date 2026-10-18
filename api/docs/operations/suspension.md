# Suspending an organization or blocking an account

Design and guarantees: `docs/architecture/organization-suspension.md`.

## When

- **Suspend an organization** when the organization itself is the problem:
  abuse of the platform (phishing or malware shared through it, scanning
  targets it does not own), non-payment on a hosted service, a legal hold.
  Nothing is deleted; every credential stops at the next request.
- **Block an account** when one person is the problem: a compromised or
  abusive account. It is refused in every organization it belongs to.
- For a single organization's member, the organization's own owners disable
  or offboard the member instead (member lifecycle); the platform block is
  for the platform operator.

## How

Both need the ops_admin or super_admin console role and a fresh
authenticator code, and ask for a reason (kept in the admin audit log, never
shown to the organization).

1. **Console > Organizations**, open the organization, **Suspend**. Members
   see "This organization is suspended — contact support" at sign-in and on
   every request; open browser tabs and live connections drop.
2. **Console > Users**, open the account, **Block**. Its sessions end at once
   and it cannot sign in.

The same actions over the API:

```
POST /api/v1/admin/tenants/{tenantId}/suspend      {"reason": "..."}
POST /api/v1/admin/tenants/{tenantId}/unsuspend    {"reason": "..."}
POST /api/v1/admin/platform-users/{id}/block       {"reason": "..."}
POST /api/v1/admin/platform-users/{id}/unblock     {"reason": "..."}
```

with the console session and the `X-Admin-Step-Up` header.

## Checking

- The organization list filters by status (`?status=suspended`).
- Every action is a **critical** row in Console > Audit log
  (`organization.suspended`, `organization.unsuspended`,
  `platform_user.blocked`, `platform_user.unblocked`).
- A suspended organization's own audit log shows "A platform administrator
  suspended this organization" without the reason.

## Lifting

Unsuspend restores every credential as it was; schedules that came due
during the suspension run on their next tick. Unblock lets the account sign
in again; its old sessions stay ended.

## If Redis is down

The access gate reads the database directly; a change still applies on the
next request. If the database cannot be read, requests are refused (fail
closed) until it can.
