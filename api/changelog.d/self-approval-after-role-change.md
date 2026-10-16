### Security: no owner self-approval right after an approver was demoted or a role changed

- The 7-day wait before an owner may approve their own exposure disposition
  or suppression rule now also starts when a member's role changed
  (`member.role_changed`, `user.roles_updated`, `role.unassigned`) or a role
  was changed or deleted (`role.updated`, `role.deleted`), not only when a
  member was suspended, removed or offboarded. Demoting the other approver to
  viewer, or stripping the approve permission from their role, no longer
  opens the path at once. One shared query decides it for every path.
