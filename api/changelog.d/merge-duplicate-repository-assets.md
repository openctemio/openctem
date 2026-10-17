### Added: `repomerge` merges duplicate repository assets

- One repository could be two assets: repository import named it `org/repo` and CI `github.com/org/repo`, or
  a rename or transfer made CI create a second asset while the first kept the findings, branches, gate policy
  and coverage expectation. `repomerge` (in the API image as `/app/repomerge`) finds such groups per tenant
  (same repository id on the same host, `host/path` with `path` on that host, a CI pipeline whose runs are on
  another asset) and merges each into its oldest asset through the asset merge: findings, branches, baseline,
  gate policy, expectations, pipelines and runs move; the kept asset takes the current `host/path` name.
- **Upgrade note:** run `repomerge` (a read-only dry run printing aggregate counts), then `repomerge -apply`.
  It is idempotent and tenant-scoped; no migration.
