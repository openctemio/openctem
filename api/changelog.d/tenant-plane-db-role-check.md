### Security: a tenant-plane API refuses to start in production when its database role can write administrators

- With `OPENCTEM_PLANE=tenant` the API always checks its database role's
  privileges on `admin_users` (before, only when `DB_ADMIN_USER` was set), and
  in production refuses to start if `DB_USER` can write it or the check cannot
  run. Run the least-privilege bootstrap with `admin_user` (the db-roles job).
- A test walks the registered routes and fails if a tenant-plane process holds
  any `/api/v1/admin` route.
