### Changed: 117 redundant indexes dropped

- Migration 001057 drops indexes that another index on the same table
  already covers: exact duplicates (usually a plain index next to the UNIQUE
  constraint on the same column) and left prefixes of a wider btree index
  with the same predicate. Queries use the covering index instead; writes
  and vacuum get cheaper. No index that backs a primary key, unique
  constraint or foreign key is dropped. The down migration recreates them.
