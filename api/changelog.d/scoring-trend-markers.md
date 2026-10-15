### Added: trend charts mark scoring changes; risk snapshots record their scoring versions

- `risk_snapshots` gets `risk_version` and `priority_version`: the scoring versions the day's numbers were computed with (migration 002192). Past snapshots are never recomputed.
- `GET /dashboard/risk-trend` points carry their versions and the scoring changes that took effect there (`scoring_changes`: date, kind, source, summary). Listed changes are the organization's own and platform model versions.
- The dashboard's priority charts draw a dashed line at each change and explain it ("Scoring changed on <date> (<what>): values before and after are not directly comparable").
