### Added: the vulnerability feed's alias dictionary is imported with each bundle

- After a bundle is applied, the importer verifies the release's signed alias manifest (pinned root's key set, schema, the applied sequence, validity, entries SHA-256) and applies a dictionary version it has not applied yet, merging feed-created duplicate products into their canonical product (merge limit max(500, 5% of the entries)).
- The feed status records `aliases_version`, `aliases_entries`, `aliases_coverage` and, for a refused dictionary, `aliases_error`; a refused dictionary never undoes the corpus import.
- Each entry's basis (reviewed `curated` or learned) is passed to the catalog, so a learned entry never folds a product with data of its own; such entries are counted in `aliases_held` and listed in `aliases_held_values` for review, and `aliases_removed` counts feed aliases the new dictionary dropped. An older dictionary version next to a newer release is ignored.
