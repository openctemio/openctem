### Security: owner recovery needs a reason and a fresh authenticator code

- `POST /api/v1/admin/tenants/{tenantId}/users` with `"recovery": true` (super admin, every owner suspended) now also requires `reason` (10 to 500 characters, kept in the admin audit log) and `totp_code`, a fresh code from the console authenticator. Without them it answers 400 or 401 `STEP_UP_REQUIRED`, and nothing is created.
- **Upgrade note:** scripts that call owner recovery must send both fields.

### Added: organization 360 in the platform admin console

- Organizations > an organization opens on a summary: owners and members, plan and over-limit, sign-in and domains, and the latest administrator actions, each leading to its tab. Tabs are in the URL (`?tab=`), and the new Activity tab lists every administrator action on the organization. Members offers "Recover ownership" to a super admin when every owner is suspended.
- The organization list shows the plan and filters by owner (`owner=none|present`) and plan (`plan=free|pro|enterprise`) on `GET /api/v1/admin/tenants`. The overview's "organizations without an owner" opens that filtered list.
