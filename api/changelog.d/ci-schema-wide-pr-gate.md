### Changed: a pull request that changes the schema runs the schema-wide tests

- A pull request that changes a migration, the role script, the Postgres repositories or the tenant-table lint now runs the few tests that read every table (`Schema-wide tests (PostgreSQL)`): tenant table list, the schema-wide delete seeder, duplicate indexes and the merge reference coverage. They used to run only in the merge queue, so a new table could pass on the pull request and then fail in the queue. Other pull requests are unchanged.
