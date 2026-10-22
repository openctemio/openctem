### Added: Bulk change of every finding a filter selects

- `POST /findings/bulk/by-filter/status` and `POST /findings/bulk/by-filter/assignee` apply a change to every finding the
  list's filter selects, recompiled on the server in the caller's data scope. `expected_count` must match (409
  `SELECTION_CHANGED` with the new count otherwise). The cap is 10,000 findings. Up to 1,000 run in the request; more
  run in the background as an operation.
- False positive, accepted risk and duplicate are never set by filter. A closing status needs step-up and a note.
- Each organization may change 20,000 findings by filter per hour. Each person may have one operation running.
- Every run writes summary audit rows, and every changed finding gets its own row.
- `GET /operations/{id}` reads an operation (creator only). New table `operations`, migration `003285_operations`
  (new and empty; no change to existing tables).
