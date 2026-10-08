### Security: repository import builds its branch-sync client from a tenant-scoped lookup

- The SCM client for branch sync during repository import loaded the
  integration by id alone. The caller had already checked ownership, so this
  was not reachable across tenants, but the lookup is now tenant-scoped like
  every other integration read (RFC-049 F-13).
