### Added: a receipt for every upload and sensor run

- Every upload and every sensor run (a scan run, a command outside a run, a CI run, a connector sync, a report a sensor pushed on its own) now gets a receipt of what it did to the organization's findings: created, still detected, reopened, closed, untouched, skipped and failed, with a per-finding action log (`finding_ingest_actions`, at most 50,000 rows per receipt, kept 90 days) and a daily ingest-outcome fact for the dashboards (`dash_ingest_day`, kept 13 months). Migration `003293_ingest_receipts`. Design: RFC-122.
- A receipt never decides anything: findings are still closed only by the coverage rules of a covered sensor run and by a source's own mitigation statement; an upload's coverage stays partial and closes nothing.
- One upload request now has one receipt for all its files (it was one record per file); `files[].import_id` is that receipt for every file and the response adds `receipt_id`.
- **Upgrade note:** the migration renames `finding_imports` to `ingest_receipts`. Replace the API together with the migration; an import made by an old API process after the migration ran fails and can be repeated.
