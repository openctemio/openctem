### Changed: PostgreSQL 16, 17 and 18 are supported; 17 is recommended

- A nightly workflow (and a push to `develop` that changes a migration, the role script or the PostgreSQL repositories) applies every migration as the non-superuser migrator and runs the DB-backed packages as the app role on PostgreSQL 16 and 18. PostgreSQL 17 stays the version the whole suite runs on for every pull request.
- The install and requirements documentation and the Helm chart values state the supported range.
- No operator action. Do not change the major version of an existing data directory except by the database's own dump/restore or `pg_upgrade`.
