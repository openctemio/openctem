### Fixed: backup.sh restore works on databases with partitioned tables
- `backup.sh restore` restored with `pg_restore --clean`, which fails on `asset_change_events_default` ("cannot drop inherited constraint") and so failed every restore drill. It now restores into a new database and swaps it in; a failed restore leaves the running database unchanged.
