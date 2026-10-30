### Added: Ready to close proposals and Recently auto-closed

- A close that the organization's closing mode or the tier rule sends to a person is now stored as a proposal (one pending per finding, with the evidence of the scan), and every candidate of a run held by the blinding guard is proposed instead of only logged. Applies when `INGEST_COVERAGE_AUTO_RESOLVE` is `enforce` (or `tenant`).
- `GET /api/v1/findings/closure/proposals` and `POST /api/v1/findings/closure/proposals/decide` (confirm or dismiss up to 200, `findings:verify`, step-up on every confirm, eligibility re-checked, audited).
- `GET /api/v1/findings/closure/auto-closed` (last 7 days) and `POST /api/v1/findings/{id}/reopen-not-fixed`.
- The bootstrap carries `badges.ready_to_close` for verifiers.
