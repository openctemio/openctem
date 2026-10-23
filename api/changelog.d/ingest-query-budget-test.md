### Changed: ingest SQL statement budget in CI

- A test imports a fixed CTIS report and re-imports it three times (unchanged, one finding gone, one new), counts the SQL statements of each phase and fails when a phase exceeds the checked-in budget (`api/tests/integration/testdata/ingest_budget.json`), so an N+1 on the import path is caught in review. `make budgets-update` rewrites the budget from a measured run.
- No operator action; no runtime change.
