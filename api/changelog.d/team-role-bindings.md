### Added: teams can carry roles

- A custom role can be bound to a team (`GET/POST /api/v1/groups/{groupId}/roles`,
  `DELETE /api/v1/groups/{groupId}/roles/{roleId}`): every active member of
  the team holds it (migration 001543, view `v_user_role_grants`).
- Binding, and changing who is in a team that carries roles, are grants: the
  actor must be able to grant each role and hold the team's assets; nobody
  but the owner adds themselves. Roles with full data access or member, team,
  role, API key, secret store or settings administration are bound, and
  their teams changed, by the owner only with a recent sign-in. External
  members never get full data access through a team. Only custom roles of
  the organization bind; a bound role cannot be deleted.
- Permission changes reach team members at once (cache invalidation), and a
  team membership past its end date stops granting immediately.
