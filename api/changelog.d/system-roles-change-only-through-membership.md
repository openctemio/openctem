### Security: system roles change only through the membership; the owner role is never granted by a role assignment

- The Roles API (`/users/{id}/roles`, `/users/{id}/roles/{roleId}`,
  `/roles/{roleId}/members/bulk`) and team role bindings now take custom roles
  only. Granting or removing `owner`, `admin`, `member` or `viewer` there is
  refused with a 400, the owner role included. Before, an owner could grant the
  owner role to a co-owner whose membership still read `admin`; the real owner
  could then not take it back, and the organization's owner counts missed them.
  A system role changes with the member's role
  (`PATCH /tenants/{tenant}/members/{id}`) and ownership with the ownership
  transfer. `PUT /users/{id}/roles` replaces custom roles and keeps the team
  role; it accepts an empty list.
- A database trigger refuses an owner role row unless the membership label is
  `owner`. Existing rows that already break this are left in place; list them
  with the query in `api/docs/architecture/authorization-matrix.md` ("Owner role
  without the owner membership") and resolve them per organization.
- Owner and admin counts, approver feasibility, notification recipients and the
  platform console read the effective role (`v_user_effective_role`) instead of
  the raw membership label. `tools/lint/rawrole` bans new raw label reads.
- Web: the Members page "Change roles" dialog now has a role-in-organization
  selector (administrator for the owner only) and lists custom roles; the role
  detail sheet of a team role no longer adds or removes members through the
  Roles API.
- A co-owner planted before this change (owner role row, membership label not owner) is removed by the real owner through the member role route, with a fresh step-up; the change is audited as `owner_role_drift_removed` (Critical).

Upgrade note: API clients that assigned `admin`, `member` or `viewer` through
`/users/{id}/roles` must use the member role route instead.
