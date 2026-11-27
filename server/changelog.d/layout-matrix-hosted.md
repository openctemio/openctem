### Added: layout matrix on GitHub-hosted runners

- `.github/workflows/layout-matrix.yml` (on demand) runs the MVP v2 layout matrix for the given routes, tenant app or platform console, in parallel shards against the e2e stack of `web/e2e/ci`, and merges the per-route detector totals into the run summary and one artifact. New in `web/e2e/ci`: `layout-matrix.sh` (one shard), `seed-matrix.sh` (API keys, SLA policies and notification channels, fixture data only) and `console.compose.yml` (the console listener).
- Docs: server/docs/development/ci-cd.md
