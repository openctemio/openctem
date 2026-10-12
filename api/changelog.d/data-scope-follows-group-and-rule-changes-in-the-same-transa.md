### Security: data scope follows group and rule changes in the same transaction

- `user_accessible_assets` is now kept in step with its sources by database
  triggers, in the writing transaction (migration **001051**, RFC-050 W6):
  group asset assign/unassign, a member leaving a group, a group deactivated,
  re-activated or deleted, a scope rule deactivated or deleted. Before, a
  deactivated or deleted access group kept granting its assets indefinitely
  (research 21b H6/L-12), a deactivated or narrowed scope rule kept what it
  had granted (M-2), and a deleted rule's rows were orphaned.
- Narrowing or deactivating a scope rule reconciles the whole group (stale
  auto-assignments removed); an asset-group membership change reconciles the
  rules of its tenant (the lookup used a zero tenant id and never matched, M-3).
- The migration removes the rows of rules that are already deactivated and
  runs one full refresh to repair scope rows left by the old behaviour.
