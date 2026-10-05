### Security: member lifecycle (disable, offboard, erase), one switch for leavers

- **Nobody is hard-deleted any more** (RFC-050 §2, owner decision 2026-10-04).
  Removing a member used to delete the membership and clean only its roles, so
  groups, grants and scope rows survived and a re-invite restored the old
  access (research 21b L-13 / M-19).
- **Disable** (the existing suspend) now also suspends the member's API and
  MCP keys, drops their scope rows and pauses the scan schedules, report
  schedules and workflows they own (administrators are notified), in one
  transaction. Groups, grants and ownership stay frozen; **re-enable**
  restores the keys and the scope (paused schedules stay paused).
- **Offboard** (`POST /api/v1/tenants/{t}/members/{id}/offboard`, and
  `DELETE /members/{id}`): mandatory reassignment of owned schedules, open
  assigned findings (or back to the queue) and owned assets to another active
  member; keys revoked; group memberships, grants, engagement memberships,
  roles and invitations removed; the membership stays as an `offboarded`
  tombstone. A plan that leaves owned work uncovered answers 409
  `reassignment_required`. A re-invite starts from zero. SCIM delete offboards
  (or disables and asks administrators when the member owns work).
- **Erase personal data** (`POST /members/{id}/erase`, owner only, after
  offboarding): name and email anonymised to `Deleted user #<hash>`; rows and
  foreign keys stay.
- `GET /members/{id}/access-report` lists what a member holds and owns;
  `GET /members?status=active|suspended|offboarded|all` (default leaves
  tombstones out, so pickers never offer a person who left).
- **Fail closed everywhere:** every membership gate admits an active
  membership only (a status other than active is refused), an inactive
  account is refused on every request (not only at login), scope rows exist
  only for an active principal (`principal_is_active` in every refresh
  function), an inactive member gets no full-data bypass, and a background
  job acting for a disabled or offboarded administrator refuses.
- **Migration 001044** adds the `offboarded` membership status
  (`offboarded_at`, `offboarded_by`), the `suspended` API key status,
  `users.erased_at`, the `principal_is_active` and `refresh_access_for_user`
  functions, gates the refresh functions and drops scope rows of members who
  are already suspended (their access was already refused at the request
  gate).
