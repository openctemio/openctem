### Fixed: deleting findings no longer scans the findings table per row

- Migration `002919_findings_duplicate_of_index` adds a partial index on `findings (duplicate_of)`. The
  self-reference's `ON DELETE SET NULL` action looked up the duplicates of every deleted finding with a full table
  scan; deleting 500 findings of a 200k-finding tenant took about 17 s.
- **Upgrade note:** no action. The index is built `CONCURRENTLY` (the table stays writable); on a large findings
  table the migration step takes as long as one pass over the table.
