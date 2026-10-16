### Security: the platform console's identity tables can get their own database role

- New optional `DB_ADMIN_USER` / `DB_ADMIN_PASSWORD`. With it, the
  least-privilege bootstrap (`-v admin_user=...`) creates a console role that
  alone writes `admin_users`, `admin_credentials`, `admin_sessions`,
  `platform_identity_provider` and `admin_idp_login_states`; the API's
  `DB_USER` keeps only `SELECT` on `admin_users`. The API opens a second small
  pool with it for the console's repositories, so a SQL injection in the tenant
  plane cannot add an administrator or read a console session.
- Compose: `db-roles` passes `admin_user` when `DB_ADMIN_USER` is set, and a new
  `db-grants` job reruns the script after `migrate`, before the API, so a table
  a migration just created gets its grants on the same `up`.
  `deploy/.env.example` and `setup.sh` set the role up for new installations;
  existing ones are unchanged until they add the two variables.
- `bootstrap-admin` and `rekey` connect as `DB_ADMIN_USER` when it is set.
- The API logs an error at start-up when `DB_ADMIN_USER` is set but the app
  role can still write `admin_users`.
