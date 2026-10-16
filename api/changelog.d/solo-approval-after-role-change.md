### Security: no sole-member finding self-approval right after an approver was demoted or a role changed

- The 7-day wait before the sole owner may approve their own finding request
  now also starts when a member's role changed (`member.role_changed`,
  `user.roles_updated`, `role.unassigned`) or a role was changed or deleted
  (`role.updated`, `role.deleted`). The same shared query as the exposure and
  suppression self-approval paths decides it.
