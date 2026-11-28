### Changed: pull requests run the DB tests they change

- API CI now runs, on a pull request, the DB-backed tests of the `*_db_test.go`
  files it adds or changes and of the ones named after a Go file it changes,
  against Postgres and Redis (`DB tests (changed files)`). A broken DB test now
  fails on its pull request instead of evicting a merge-queue group. Skipped
  when no such file changed; the merge queue still runs the whole suite.
- Docs: server/docs/development/ci-cd.md
