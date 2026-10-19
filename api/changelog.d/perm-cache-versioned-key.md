### Security: a revoked permission can no longer be written back into the permission cache

- A request that loaded a user's permissions from the database just before an administrator revoked
  one could store the old set in the cache after the revocation cleared it, and the revoked
  permission kept working for up to five minutes (for writes too, once the user refreshed the
  token). Cached permission sets are now keyed by the user's permission version, read before the
  database, so the old set is stored under a version no later request reads. When the version cannot
  be read, permissions come from the database and the cache is not used.
- Removing, suspending or demoting a member now bumps their permission version instead of deleting
  it, so an entry cached before their first version can never be read again. Their live sockets are
  closed as before.
- **Upgrade note:** none; entries under the old key format expire within five minutes.
