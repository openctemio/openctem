# RFC-127: Team access presets

| | |
|---|---|
| Status | Accepted (2026-10-26). Shipped with migration `003433_team_access_presets` |
| Scope | api (`internal/app/accesscontrol/group_access.go`, `pkg/domain/role`, `pkg/domain/group`, group routes), web (settings, team form and member profile) |
| Architecture | [authorization-matrix.md](../architecture/authorization-matrix.md) (Team access presets) |
| Related | RFC-095 (role templates and invitations), RFC-058 (outside members), the team role bindings in the authorization matrix |

## 1. Summary

A team gives its members data scope (scope rules and assigned assets) and, since
team role bindings, the permissions of the custom roles bound to it. Until now
the owner had to create a custom role first. A team now carries access in one
step: its **Access** settings name one or more **presets** (role templates) and a
**scope mode**. Adding people to the team is then all that is needed: they
inherit both at once, and lose both when they leave the team or their
membership ends.

## 2. Decisions

| ID | Decision |
|---|---|
| D1 | A preset creates a **managed role** of the team (`roles.managed_group_id`, template id and version recorded), bound to the team. No manual role step. Several presets are a union. |
| D2 | **All assets** is a team scope mode: a managed role with full data access and no permissions. The data-scope engine, notification audiences and every full-data guard read it exactly as they read `has_full_data_access`. Owner only, with step-up, audited. |
| D3 | Owner and admin are never granted through a team: only custom roles bind, and the schema refuses system roles. |
| D4 | A team is **privileged** when any of its roles is (all assets, or a preset with a privileged permission). Only an owner sets or changes a privileged team's access or the team itself, with a recent sign-in. Adding or removing people in a privileged managed team needs `team:members:write` on top of the team permission, so a team lead who holds only team permissions cannot. |

## 3. Design

### 3.1 Managed roles

A managed role is an ordinary custom role of the organization, owned by one team:

- created, upgraded and deleted only through the team's access settings;
- not editable (`PUT /roles/{id}`), not deletable, not assignable to a person, not
  usable in an invitation or provisioning request, and not bound or unbound by
  hand (`ErrManagedRole`, 400);
- the database refuses the same moves (triggers on `user_roles` and
  `group_role_bindings`), and deleting the team deletes its managed roles;
- hidden from `GET /roles` (the roles an organization manages by hand); the team
  shows them (`GET /groups/{id}/roles` marks them `managed`).

A managed role follows its template: the role records the template version it took.
When the catalog has a newer version the team shows "update available"; applying
it (`POST /groups/{id}/access/upgrade`, with the version the editor reviewed)
sets the role to the template's current permissions. Full data access of a role
is never changed by an update.

### 3.2 API

| Route | Gate |
|---|---|
| `GET /api/v1/groups/{groupId}/access` | `team:groups:read` and `team:roles:read` |
| `PUT /api/v1/groups/{groupId}/access` | `team:roles:assign` and `team:groups:write` |
| `POST /api/v1/groups/{groupId}/access/upgrade` | `team:roles:assign` and `team:groups:write` |
| `GET /api/v1/users/{userId}/team-access` | `team:groups:read` and `team:roles:read` |

`PUT` takes `{presets: [template ids], scope_mode: "specific" | "all_assets"}` and
makes the team's presets exactly that set. It adds the managed roles that are
missing, removes the ones no longer named and changes nothing else. The
`team-access` read lists what a person inherits ("access from team X"): the team,
the role, whether it is a preset and the end date of their membership.

### 3.3 Guards

- The actor holds every permission of a preset they add or remove (the grant
  ceiling) and, without full data access, every asset of the team.
- A non-owner who belongs to a team does not add roles to it.
- Privileged teams: owner only, recent sign-in, `Critical` audit. This covers
  adding or removing all assets or a privileged preset, and renaming or
  deactivating the team.
- An outside member or a service account never joins a team that sees all assets,
  and all assets is not set on a team that has one. An outside invitee to a team
  with elevated access is flagged for the existing outside-member checks, so the
  two-factor rules apply to team-derived access as to direct grants.
- Every change drops the cached permissions of the members.
- Audit: `role.assigned` and `role.unassigned` per role (as for bindings) and one
  `group.updated` summary with the scope mode and presets.

### 3.4 Tenant isolation

Every lookup is scoped by the caller's tenant: the team, the managed role
(composite foreign key `(managed_group_id, tenant_id)`), the bindings and the
member grants. Another organization's team or person answers 404 or an empty list.

## 4. Not in this RFC

Per-team "access until" and SCIM group mapping to a team are separate changes.
