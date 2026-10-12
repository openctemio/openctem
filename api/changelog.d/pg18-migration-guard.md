### Fixed: migrations and the sensor upgrade check run on PostgreSQL 18

- Migration 001483 (`drop_dead_columns`) stopped on PostgreSQL 18 and left the
  database dirty: its safety guard, which refuses to drop a column another
  constraint still uses, also counted the column's own NOT NULL, which
  PostgreSQL 18 records in `pg_constraint`. The guard now ignores NOT NULL
  constraints; nothing changes on PostgreSQL 17 or for a database that has
  already applied 001483.
- The post-upgrade sensor rename check (run at every server start) no longer
  reports `<table>_user_agent_not_null` on PostgreSQL 18 as a leftover.
- API CI applies every migration to PostgreSQL 18 as well.
- **Upgrade note:** a PostgreSQL 18 database left dirty at 1483 is unchanged
  (the failed migration rolled back). Run `migrate ... force 1481`, then the
  migrations of this release (`migrate ... up`).
