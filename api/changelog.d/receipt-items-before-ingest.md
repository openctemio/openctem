### Fixed: a run's held and refused findings are on its receipt item log

- A finding the output-type binding held for review is now an item of the run's receipt (`quarantined`, reason `held_for_review`, or `rejected`, `quarantine_full` when the quarantine could not keep it), and a protocol v2 finding that names no asset of its segment is one too (`rejected`, `unresolved_ref`). Before, these findings were dropped before the finding processor and left nothing on `GET /findings/imports/{id}/items`, which is why the item log stayed empty while scans lost findings. No migration.
