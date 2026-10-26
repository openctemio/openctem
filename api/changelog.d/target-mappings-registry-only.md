### Changed: target mappings hold only administrators' additions; the asset type catalog is the built-in source

- Which asset types a scanner target type can scan is decided by the asset type catalog (`scannable_by`). The target mapping table duplicated most of it with seeded rows that changed nothing. Migration `target_mappings_registry_covered_seed_rows` removes the 32 seeded rows the catalog already declares (the 6 seed rows that go beyond it, and every row an administrator created, stay), so scans decide exactly as before.
- `POST /admin/target-mappings` refuses a pair the catalog already has (409). `GET /admin/target-mappings/registry` lists the built-in pairs, and the console shows them read-only under the custom mappings.
- Upgrade note: the down migration puts the removed seed rows back with their original ids.
