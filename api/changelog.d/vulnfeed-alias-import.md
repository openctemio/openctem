### Added: the vulnerability feed's alias dictionary is imported with each bundle

- After a bundle is applied, the importer verifies the release's signed alias manifest (pinned root's key set, schema, the applied sequence, validity, entries SHA-256) and applies a dictionary version it has not applied yet, merging feed-created duplicate products into their canonical product (merge limit max(500, 5% of the entries)).
- The feed status records `aliases_version`, `aliases_entries`, `aliases_coverage` and, for a refused dictionary, `aliases_error`; a refused dictionary never undoes the corpus import.
