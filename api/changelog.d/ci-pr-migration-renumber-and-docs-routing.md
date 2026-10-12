### Changed: pull request CI survives migration number clashes and skips code suites for docs

- PR CI renumbers, in the runner only, a PR's migrations whose number
  develop took in the meantime, so the DB-backed tests run on the tree the
  merge queue will merge instead of failing on a duplicate version. A
  duplicate between the PR and its base is a warning on the PR; the merge
  queue and pushes still fail it.
- Documentation (`*.md`, `api/docs/**`, agent notes) no longer starts the Go
  or web suites or the API/Web Security workflows; the changelog check moved
  to API CI's always-running `changes` job.
- Docs check cancels superseded PR runs; the secret-scan and workflow-lint
  tool downloads retry.
