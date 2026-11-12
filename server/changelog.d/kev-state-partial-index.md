### Changed: the KEV sync no longer reads the whole vulnerability state table

- Migration `20261101083322_vuln_event_state_in_kev_index` adds a partial index on the KEV flag (built concurrently, no write lock). The sync's three statements now probe it instead of scanning about 345 000 rows: on a restored copy of the UAT database the removal update went from 16-22 ms to 2-6 ms, the state upsert from 23-29 ms to under 1 ms, and the event insert from 47-53 ms to about 1 ms. The upsert also stops locking every already-flagged row on each sync.
