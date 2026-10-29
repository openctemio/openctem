### Changed: CI runs the full suite once per pull request, in the merge queue

- A pull request now runs a fast tier: lint, type-check, build, and the unit tests of the Go packages it changed (and everything that imports them), plus the e2e smoke set when `web/` changed. The Postgres suite with the race detector, PostgreSQL 18 and the whole e2e suite run in the merge queue, which is authoritative. The `ci:full` label (or a changed CI definition) still runs the full tier on the PR.
- API CI, Web CI and Web E2E skip in the queue when the part they test is identical to a commit already verified by a full-tier run (the queue entry ahead of the group, or develop). Required check names are unchanged and report success when skipped.
