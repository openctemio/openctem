### Fixed: an organization whose only owner is blocked or erased can now be recovered

- A platform administrator blocking (or erasing) the sole owner's account left the organization unmanageable: the Organizations list still showed the owner, Overview raised no "without owner" item, the Users tab hid the recovery action and the API answered "has an active owner". Owner recovery, the list's owner filter, Overview and the Users tab now share one definition of an owner who can act (active membership, account active and not erased).
- `GET /api/v1/admin/tenants/{id}/users` returns `active_owner_count`, so a read-only administrator no longer sees a wrong "every owner is suspended" notice.
