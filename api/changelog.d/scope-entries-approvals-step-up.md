### Security: widening scope needs re-authentication, approval and notifies every administrator

- Scope targets gain an expiry, a reason, a tier ceiling and widening
  approvals (RFC-054, migration `001198`, new permission
  `attack_surface:scope:approve` for owners and admins).
- Creating, activating, extending or raising the tier of a scope target asks
  for step-up re-authentication and, in an organization with two or more
  administrators, the approval of another administrator before it takes
  effect (`POST /api/v1/scope/targets/{id}/approve`, `.../reject`). Removing,
  deactivating or shortening a scope exclusion asks for step-up too.
- One-off entries expire (default 7 days, at most 30) and stop authorizing
  the moment they expire.
- Every widening and every new request notifies all administrators in-app;
  approvals, rejections and settings changes are audited.
- New `GET/PUT /api/v1/scope/settings`: auto-join of discovered names, who
  may add one-off entries, their maximum days, the approval count and the
  default tier. There is no setting that turns scope off.

### Behaviour change: members request scope targets instead of creating them

- A member with `attack_surface:scope:write` but without
  `attack_surface:scope:approve` can no longer add a permanent scope target.
  They request a one-off entry for one name or address, with a reason, and an
  administrator approves it.
- **Upgrade note:** existing scope targets are unchanged (active, permanent,
  `t1`). A deactivated target is re-activated by an administrator.
